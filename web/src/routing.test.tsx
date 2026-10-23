import { QueryClientProvider } from '@tanstack/react-query';
import { createMemoryHistory, createRouter, RouterProvider } from '@tanstack/react-router';
import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ThemeProvider } from './ds/theme/ThemeProvider';
import { routeTree } from './routeTree.gen';
import { createTestQueryClient } from './test/utils';

function json(status: number, body: unknown, type = 'application/json') {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': type } });
}

function renderAt(path: string) {
  const queryClient = createTestQueryClient();
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider mode="light">
        <RouterProvider router={router} />
      </ThemeProvider>
    </QueryClientProvider>,
  );
  return router;
}

class SilentEventSource {
  readyState = 0;
  onopen = null;
  onerror = null;
  addEventListener(): void {
    // no events in these tests
  }
  close(): void {
    this.readyState = 2;
  }
}

describe('routing', () => {
  beforeEach(() => {
    vi.stubGlobal('EventSource', SilentEventSource);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('redirects unauthenticated visitors to /login with a return path', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url.startsWith('/api/v1/me')) {
        return Promise.resolve(
          json(401, { status: 401, code: 'unauthenticated' }, 'application/problem+json'),
        );
      }
      if (url.startsWith('/api/v1/auth/config')) {
        return Promise.resolve(json(200, { local_enabled: true, oidc_providers: [] }));
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    const router = renderAt('/requests?state=pending');
    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in to Hallpass' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
    expect(router.state.location.search).toEqual({ next: '/requests?state=pending' });
  });

  it('renders the shell and an honest placeholder for unbuilt pages when signed in', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url.startsWith('/api/v1/me')) {
        return Promise.resolve(
          json(200, {
            operator_id: 'op_1',
            display_name: 'Ada Operator',
            roles: ['administrator'],
            permissions: [],
            csrf_token: 'csrf',
            auth_time: '2026-01-01T00:00:00Z',
          }),
        );
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderAt('/agents');
    expect(await screen.findByRole('heading', { level: 1, name: 'Agents' })).toBeInTheDocument();
    expect(screen.getByText('Agents is not implemented yet')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Ada Operator/ })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole('link', { name: 'Requests' })).toHaveAttribute('href', '/requests');
    });
  });
});
