import { QueryClientProvider } from '@tanstack/react-query';
import { createMemoryHistory, createRouter, RouterProvider } from '@tanstack/react-router';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { Grant } from '../../api/types';
import { ThemeProvider } from '../../ds/theme/ThemeProvider';
import { routeTree } from '../../routeTree.gen';
import { jsonResponse, makeMe } from '../../test/fixtures';
import { createTestQueryClient } from '../../test/utils';

class SilentEventSource {
  readyState = 0;
  onopen = null;
  onerror = null;
  addEventListener(): void {
    // no live events
  }
  close(): void {
    this.readyState = 2;
  }
}

const grant: Grant = {
  id: 'g1',
  request_id: 'r1',
  agent_id: 'ag1',
  server_id: 'sv1',
  role_id: 'rl1',
  remote_user: 'deploy',
  capabilities: ['exec'],
  starts_at: '2026-01-01T09:59:00Z',
  expires_at: '2099-01-01T00:00:00Z',
  state: 'active',
  session_id: 's1',
};

describe('<SessionsPage>', () => {
  beforeEach(() => {
    vi.stubGlobal('EventSource', SilentEventSource);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('lists grants with URL filters and revokes with a reason and an idempotency key', async () => {
    const user = userEvent.setup();
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
      const url = input instanceof Request ? input.url : input.toString();
      calls.push({ url, init });
      if (url.startsWith('/api/v1/me')) {
        return Promise.resolve(
          jsonResponse(200, makeMe({ permissions: ['sessions.read', 'requests.read', 'grants.revoke'] })),
        );
      }
      if (url.startsWith('/api/v1/grants?')) {
        return Promise.resolve(jsonResponse(200, { items: [grant], next_cursor: null }));
      }
      if (url === '/api/v1/grants/g1/revoke') {
        return Promise.resolve(jsonResponse(200, { ...grant, state: 'revoked', end_reason: 'operator' }));
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    const queryClient = createTestQueryClient();
    const router = createRouter({
      routeTree,
      context: { queryClient },
      history: createMemoryHistory({ initialEntries: ['/sessions?tab=grants&state=active&bogus=1'] }),
    });
    render(
      <QueryClientProvider client={queryClient}>
        <ThemeProvider mode="light">
          <RouterProvider router={router} />
        </ThemeProvider>
      </QueryClientProvider>,
    );
    expect(await screen.findByRole('link', { name: 'Open session' })).toHaveAttribute('href', '/sessions/s1');
    expect(calls.find((c) => c.url.startsWith('/api/v1/grants?'))?.url).toBe(
      '/api/v1/grants?state=active&limit=50',
    );
    expect(router.state.location.search).toMatchObject({ tab: 'grants', state: 'active' });

    await user.click(screen.getByRole('button', { name: 'Revoke grant g1' }));
    await user.type(await screen.findByLabelText(/Reason/), 'suspicious activity');
    await user.click(screen.getByRole('button', { name: 'Revoke grant' }));
    await waitFor(() => {
      expect(calls.some((c) => c.url === '/api/v1/grants/g1/revoke')).toBe(true);
    });
    const post = calls.find((c) => c.url === '/api/v1/grants/g1/revoke');
    expect(JSON.parse(post?.init?.body as string)).toEqual({ reason: 'suspicious activity' });
    expect(new Headers(post?.init?.headers).get('Idempotency-Key')).toMatch(/.+/);
    expect(new Headers(post?.init?.headers).get('X-CSRF-Token')).toBe('csrf-test');
  });

  it('shows permission denied without sessions.read and requests.read', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      return url.startsWith('/api/v1/me')
        ? Promise.resolve(jsonResponse(200, makeMe({ permissions: ['dashboard.view'] })))
        : Promise.reject(new Error(`unexpected ${url}`));
    });
    const queryClient = createTestQueryClient();
    const router = createRouter({
      routeTree,
      context: { queryClient },
      history: createMemoryHistory({ initialEntries: ['/sessions'] }),
    });
    render(
      <QueryClientProvider client={queryClient}>
        <ThemeProvider mode="light">
          <RouterProvider router={router} />
        </ThemeProvider>
      </QueryClientProvider>,
    );
    expect(await screen.findByText("You don't have access")).toBeInTheDocument();
  });
});
