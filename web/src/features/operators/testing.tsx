import { QueryClientProvider } from '@tanstack/react-query';
import { createMemoryHistory, createRouter, RouterProvider } from '@tanstack/react-router';
import { render } from '@testing-library/react';
import { vi } from 'vitest';

import { ThemeProvider } from '../../ds/theme/ThemeProvider';
import { routeTree } from '../../routeTree.gen';
import { createTestQueryClient } from '../../test/utils';

/** Test-only helpers for page tests in features/operators and features/me. */

export interface Call {
  method: string;
  url: string;
  body: unknown;
  headers: Headers;
}

export type Handler = (call: Call) => Response | undefined;

export function json(status: number, body: unknown, type = 'application/json'): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': type },
  });
}

class SilentEventSource {
  readyState = 0;
  onopen = null;
  onerror = null;
  addEventListener(): void {
    // no live events in page tests
  }
  close(): void {
    this.readyState = 2;
  }
}

/**
 * Mocks global fetch with `routes` (`'GET /api/v1/operators'` → handler or response factory) and records
 * every call. Unknown requests fail the test loudly.
 */
export function mockApi(routes: Record<string, (call: Call) => Response>): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal('EventSource', SilentEventSource);
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const raw = input instanceof Request ? input.url : input.toString();
    const method = init?.method ?? 'GET';
    const path = raw.split('?')[0] ?? raw;
    const call: Call = {
      method,
      url: raw,
      body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined,
      headers: new Headers(init?.headers),
    };
    calls.push(call);
    const handler = routes[`${method} ${path}`];
    if (!handler) {
      return Promise.reject(new Error(`unexpected ${method} ${raw}`));
    }
    return Promise.resolve(handler(call));
  });
  return calls;
}

/** Renders the real route tree at `path` (the `_app` guard reads GET /api/v1/me from the mock). */
export function renderAppAt(path: string) {
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
  return { router, queryClient };
}
