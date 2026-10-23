import { describe, expect, it, vi } from 'vitest';

import { ApiClient, buildQueryString, readPreSessionCsrfCookie } from './client';
import { ApiError, isApiError } from './errors';
import type { Me } from './types';

interface Call {
  url: string;
  init: RequestInit;
  headers: Headers;
}

function json(
  status: number,
  body: unknown,
  contentType = 'application/json',
  extra: Record<string, string> = {},
) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': contentType, ...extra } });
}

function problem(status: number, code: string, detail = code, errors?: unknown[]) {
  return json(
    status,
    { type: 'about:blank', title: code, status, code, detail, errors },
    'application/problem+json',
  );
}

function me(token: string): Me {
  return {
    operator_id: 'op_1',
    display_name: 'Ada',
    roles: ['administrator'],
    permissions: ['dashboard.view'],
    csrf_token: token,
    auth_time: '2026-01-01T00:00:00Z',
  };
}

/** Fake fetch answering from a queue of responders and recording calls. */
function fakeFetch(...responders: ((call: Call) => Response)[]) {
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const call: Call = {
      url: input instanceof Request ? input.url : String(input),
      init: init ?? {},
      headers: new Headers(init?.headers),
    };
    calls.push(call);
    const responder = responders.shift();
    if (!responder) {
      throw new Error(`unexpected request ${call.url}`);
    }
    return Promise.resolve(responder(call));
  });
  return { fetch: fn as unknown as typeof fetch, calls };
}

describe('ApiClient', () => {
  it('sends GETs same-origin without a CSRF header and parses JSON', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, { ok: true }));
    const client = new ApiClient({ fetch });
    await expect(client.get('/things', { query: { state: 'pending', limit: 50 } })).resolves.toEqual({
      ok: true,
    });
    expect(calls[0]?.url).toBe('/api/v1/things?state=pending&limit=50');
    expect(calls[0]?.init.credentials).toBe('same-origin');
    expect(calls[0]?.init.cache).toBe('no-store');
    expect(calls[0]?.headers.has('X-CSRF-Token')).toBe(false);
  });

  it('fetches /me for the CSRF token before the first mutation and reuses it', async () => {
    const { fetch, calls } = fakeFetch(
      () => json(200, me('tok-1')),
      () => new Response(null, { status: 204 }),
      () => json(200, { id: 'x' }),
    );
    const client = new ApiClient({ fetch });
    await client.post('/a', { x: 1 });
    await client.patch('/b', { y: 2 }, { ifMatch: 7, idempotencyKey: 'idem-1' });
    expect(calls.map((c) => c.url)).toEqual(['/api/v1/me', '/api/v1/a', '/api/v1/b']);
    expect(calls[1]?.headers.get('X-CSRF-Token')).toBe('tok-1');
    expect(calls[1]?.headers.get('Content-Type')).toBe('application/json');
    expect(calls[1]?.init.body).toBe('{"x":1}');
    expect(calls[2]?.headers.get('X-CSRF-Token')).toBe('tok-1');
    expect(calls[2]?.headers.get('If-Match')).toBe('"7"');
    expect(calls[2]?.headers.get('Idempotency-Key')).toBe('idem-1');
  });

  it('parses RFC 9457 problem details into ApiError with field errors', async () => {
    const { fetch } = fakeFetch(() =>
      problem(422, 'validation_failed', 'Name is invalid', [
        { field: 'name', detail: 'too long' },
        { pointer: '/spec/labels/0', message: 'bad label' },
        { code: 'required' },
      ]),
    );
    const client = new ApiClient({ fetch });
    const error = await client.get('/x').catch((e: unknown) => e);
    expect(isApiError(error)).toBe(true);
    const e = error as ApiError;
    expect(e.status).toBe(422);
    expect(e.code).toBe('validation_failed');
    expect(e.detail).toBe('Name is invalid');
    expect(e.fields).toEqual({ name: ['too long'], 'spec.labels.0': ['bad label'], _: ['required'] });
  });

  it('maps non-problem errors and network failures to stable codes', async () => {
    const { fetch } = fakeFetch(
      () => new Response('<html>oops</html>', { status: 502, headers: { 'Content-Type': 'text/html' } }),
    );
    const client = new ApiClient({ fetch });
    await expect(client.get('/x')).rejects.toMatchObject({ status: 502, code: 'http_502' });

    const failing = new ApiClient({ fetch: () => Promise.reject(new TypeError('Failed to fetch')) });
    await expect(failing.get('/x')).rejects.toMatchObject({ status: 0, code: 'network_error' });
  });

  it('rethrows aborts unchanged', async () => {
    const abort = new DOMException('aborted', 'AbortError');
    const client = new ApiClient({ fetch: () => Promise.reject(abort) });
    await expect(client.get('/x')).rejects.toBe(abort);
  });

  it('rejects successful responses that are not JSON', async () => {
    const { fetch } = fakeFetch(
      () => new Response('<b>hi</b>', { status: 200, headers: { 'Content-Type': 'text/html' } }),
    );
    await expect(new ApiClient({ fetch }).get('/x')).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('on reauth_required prompts, refreshes the rotated CSRF token and retries once', async () => {
    const { fetch, calls } = fakeFetch(
      () => json(200, me('old')),
      () => problem(401, 'reauth_required'),
      () => json(200, me('new')),
      () => json(200, { revoked: true }),
    );
    const client = new ApiClient({ fetch });
    const prompt = vi.fn(() => Promise.resolve(true));
    const rotated = vi.fn();
    const unauthorized = vi.fn();
    client.setHandlers({ onReauthRequired: prompt, onSessionRotated: rotated, onUnauthorized: unauthorized });

    await expect(client.post('/grants/g1/revoke', { reason: 'r' })).resolves.toEqual({ revoked: true });
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(rotated).toHaveBeenCalledTimes(1);
    expect(unauthorized).not.toHaveBeenCalled();
    expect(calls.map((c) => c.url)).toEqual([
      '/api/v1/me',
      '/api/v1/grants/g1/revoke',
      '/api/v1/me',
      '/api/v1/grants/g1/revoke',
    ]);
    expect(calls[1]?.headers.get('X-CSRF-Token')).toBe('old');
    expect(calls[3]?.headers.get('X-CSRF-Token')).toBe('new');
  });

  it('does not retry when reauthentication is declined', async () => {
    const { fetch, calls } = fakeFetch(() => problem(401, 'reauth_required'));
    const client = new ApiClient({ fetch });
    client.setCsrfToken('t');
    client.setHandlers({ onReauthRequired: () => Promise.resolve(false) });
    await expect(client.post('/x')).rejects.toMatchObject({ code: 'reauth_required' });
    expect(calls).toHaveLength(1);
  });

  it('retries at most once even if the server asks for reauth again', async () => {
    const { fetch, calls } = fakeFetch(
      () => problem(401, 'reauth_required'),
      () => json(200, me('t2')),
      () => problem(401, 'reauth_required'),
    );
    const client = new ApiClient({ fetch });
    client.setCsrfToken('t1');
    const prompt = vi.fn(() => Promise.resolve(true));
    client.setHandlers({ onReauthRequired: prompt });
    await expect(client.post('/x')).rejects.toMatchObject({ code: 'reauth_required' });
    expect(prompt).toHaveBeenCalledTimes(1);
    expect(calls).toHaveLength(3);
  });

  it('shares one reauth prompt between concurrent requests', async () => {
    const { fetch } = fakeFetch(
      () => problem(401, 'reauth_required'),
      () => problem(401, 'reauth_required'),
      () => json(200, me('n1')),
      () => json(200, me('n2')),
      () => json(200, { n: 1 }),
      () => json(200, { n: 2 }),
    );
    const client = new ApiClient({ fetch });
    client.setCsrfToken('t');
    let resolvePrompt: (v: boolean) => void = () => undefined;
    const prompt = vi.fn(
      () =>
        new Promise<boolean>((resolve) => {
          resolvePrompt = resolve;
        }),
    );
    client.setHandlers({ onReauthRequired: prompt });
    const a = client.post('/a');
    const b = client.post('/b');
    await vi.waitFor(() => {
      expect(prompt).toHaveBeenCalledTimes(1);
    });
    resolvePrompt(true);
    await expect(Promise.all([a, b])).resolves.toHaveLength(2);
    expect(prompt).toHaveBeenCalledTimes(1);
  });

  it('redirects to login on 401 unless authRedirect is false', async () => {
    const { fetch } = fakeFetch(
      () => problem(401, 'unauthenticated'),
      () => problem(401, 'invalid_credentials'),
    );
    const client = new ApiClient({ fetch });
    const unauthorized = vi.fn();
    client.setHandlers({ onUnauthorized: unauthorized });
    await expect(client.get('/me')).rejects.toMatchObject({ status: 401 });
    expect(unauthorized).toHaveBeenCalledTimes(1);
    await expect(client.post('/auth/login', {}, { csrf: 'none', authRedirect: false })).rejects.toMatchObject(
      {
        code: 'invalid_credentials',
      },
    );
    expect(unauthorized).toHaveBeenCalledTimes(1);
  });

  it('sends the pre-session CSRF token for login-type requests', async () => {
    const { fetch, calls } = fakeFetch(() => json(200, {}));
    const client = new ApiClient({ fetch });
    client.setHandlers({ getPreSessionCsrfToken: () => 'pre' });
    await client.post(
      '/auth/login',
      { username: 'a', password: 'b' },
      { csrf: 'pre-session', authRedirect: false },
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]?.headers.get('X-CSRF-Token')).toBe('pre');
  });

  it('rejects a /me response without a CSRF token', async () => {
    const { fetch } = fakeFetch(() => json(200, { ...me(''), csrf_token: '' }));
    await expect(new ApiClient({ fetch }).getMe()).rejects.toMatchObject({ code: 'invalid_response' });
  });

  it('feeds the Date header into the clock sampler', async () => {
    let t = 1_000;
    const { fetch } = fakeFetch(() =>
      json(200, {}, 'application/json', { Date: 'Thu, 01 Jan 1970 00:00:10 GMT' }),
    );
    const client = new ApiClient({
      fetch,
      now: () => {
        t += 100;
        return t;
      },
    });
    const sample = vi.fn();
    client.setHandlers({ onClockSample: sample });
    await client.get('/x');
    expect(sample).toHaveBeenCalledWith({
      serverTimeMs: 10_000,
      sentAt: 1_100,
      receivedAt: 1_200,
      resolutionMs: 1000,
    });
  });
});

describe('buildQueryString', () => {
  it('skips nullish values and repeats array values', () => {
    expect(buildQueryString({ a: 'x y', b: undefined, c: null, d: [1, 2], e: false })).toBe(
      '?a=x+y&d=1&d=2&e=false',
    );
    expect(buildQueryString({})).toBe('');
  });
});

describe('readPreSessionCsrfCookie', () => {
  it('reads only the known cookie names', () => {
    expect(readPreSessionCsrfCookie('foo=1; hp_login_csrf=abc%3D; bar=2')).toBe('abc=');
    expect(readPreSessionCsrfCookie('foo=1')).toBeNull();
  });
});
