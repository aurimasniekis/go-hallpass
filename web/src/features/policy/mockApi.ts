import { vi } from 'vitest';

import { jsonResponse } from '../../test/fixtures';

/**
 * Test-only fetch mock keyed by `METHOD /api/v1/path` (query string ignored). Records every call so tests
 * can assert bodies and headers. Unrouted requests fail loudly.
 */
export interface RecordedCall {
  method: string;
  url: string;
  path: string;
  headers: Headers;
  body: unknown;
}

export type Route = (call: RecordedCall) => Response;

export function mockApi(routes: Record<string, Route | object>) {
  const calls: RecordedCall[] = [];
  const spy = vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    const path = url.split('?')[0] ?? url;
    const raw = init?.body;
    const call: RecordedCall = {
      method,
      url,
      path,
      headers: new Headers(init?.headers),
      body: typeof raw === 'string' ? (JSON.parse(raw) as unknown) : undefined,
    };
    calls.push(call);
    const route = routes[`${method} ${path}`];
    if (route === undefined) {
      return Promise.reject(new Error(`unrouted ${method} ${url}`));
    }
    return Promise.resolve(typeof route === 'function' ? (route as Route)(call) : jsonResponse(200, route));
  });
  return { calls, spy };
}
