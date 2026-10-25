import { QueryClientProvider } from '@tanstack/react-query';
import { createMemoryHistory, createRouter, RouterProvider } from '@tanstack/react-router';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ThemeProvider } from './ds/theme/ThemeProvider';
import { routeTree } from './routeTree.gen';
import { makeMe } from './test/fixtures';
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
        return Promise.resolve(json(200, { local_login: true, providers: [], bootstrap_required: false }));
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    const router = renderAt('/requests?state=pending');
    expect(await screen.findByRole('heading', { level: 1, name: 'Sign in to HallPass' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
    expect(router.state.location.search).toEqual({ next: '/requests?state=pending' });
  });

  it('renders the shell with permission-filtered navigation when signed in', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url.startsWith('/api/v1/me')) {
        return Promise.resolve(
          json(
            200,
            makeMe({
              operator: { display_name: 'Ada Operator' },
              permissions: ['system.read', 'requests.read'],
            }),
          ),
        );
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderAt('/settings/storage');
    expect(await screen.findByRole('heading', { level: 1, name: 'Storage & keys' })).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Ada Operator/ })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole('link', { name: 'Requests' })).toHaveAttribute('href', '/requests');
    });
    // Pages outside the operator's permissions are not offered.
    expect(screen.queryByRole('link', { name: 'Operators' })).not.toBeInTheDocument();
  });

  it('puts the navigation in a drawer on phones', async () => {
    vi.stubGlobal(
      'matchMedia',
      vi.fn((query: string) => ({
        matches: query.startsWith('(max-width'),
        media: query,
        onchange: null,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(() => false),
      })),
    );
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url.startsWith('/api/v1/me')) {
        return Promise.resolve(
          json(
            200,
            makeMe({
              operator: { display_name: 'Ada Operator' },
              permissions: ['system.read', 'requests.read'],
            }),
          ),
        );
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    renderAt('/settings/storage');
    expect(await screen.findByRole('heading', { level: 1, name: 'Storage & keys' })).toBeInTheDocument();
    // No sidebar squeezing the page: the navigation opens from the header.
    expect(screen.queryByRole('navigation', { name: 'Main' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Account: Ada Operator' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Open navigation' }));
    expect(await screen.findByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Requests' })).toHaveAttribute('href', '/requests');
  });

  it('sends a limited (MFA pending) session back to /login', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url.startsWith('/api/v1/me')) {
        return Promise.resolve(json(200, makeMe({ permissions: [], session: { limited: true } })));
      }
      if (url.startsWith('/api/v1/auth/config')) {
        return Promise.resolve(json(200, { local_login: true, providers: [], bootstrap_required: false }));
      }
      return Promise.reject(new Error(`unexpected ${url}`));
    });
    const router = renderAt('/agents');
    expect(await screen.findByLabelText('Authentication code')).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
  });
});
