import { QueryClientProvider } from '@tanstack/react-query';
import { createMemoryHistory, createRootRoute, createRouter, RouterProvider } from '@tanstack/react-router';
import { render } from '@testing-library/react';
import { App } from 'antd';
import type { ReactElement } from 'react';
import { vi } from 'vitest';

import { ThemeProvider } from '../../ds/theme/ThemeProvider';
import { jsonResponse } from '../../test/fixtures';
import { createTestQueryClient } from '../../test/utils';

/**
 * Test-only helpers for the Fork A pages: render inside a minimal memory router (for <Link>) and route a
 * mocked global fetch by method + path. Fixtures are generated per test and hold no secrets.
 */
export function renderInRouter(ui: ReactElement) {
  const queryClient = createTestQueryClient();
  const rootRoute = createRootRoute({ component: () => ui });
  const router = createRouter({
    routeTree: rootRoute,
    history: createMemoryHistory({ initialEntries: ['/'] }),
  });
  const result = render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider mode="light">
        <App>
          <RouterProvider router={router} />
        </App>
      </ThemeProvider>
    </QueryClientProvider>,
  );
  return { ...result, queryClient };
}

export interface SeenRequest {
  method: string;
  url: string;
  headers: Headers;
  body: unknown;
}

export type Route = (req: SeenRequest) => Response | undefined;

/** Mocks global fetch; the first route returning a Response wins. Unmatched requests fail loudly. */
export function mockApi(...routes: Route[]) {
  const seen: SeenRequest[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const req: SeenRequest = {
      method: init?.method ?? 'GET',
      url,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined,
    };
    seen.push(req);
    for (const route of routes) {
      const res = route(req);
      if (res) {
        return Promise.resolve(res);
      }
    }
    return Promise.reject(new Error(`unexpected ${req.method} ${url}`));
  });
  return seen;
}

/** Route helper: `on('GET', '/api/v1/me', body)` (path prefix match ignoring the query string). */
export function on(method: string, path: string, body: unknown, status = 200): Route {
  return (req) =>
    req.method === method && req.url.split('?')[0] === path ? jsonResponse(status, body) : undefined;
}
