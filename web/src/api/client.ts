import { recordClockSample, type ClockSample } from '../stores/clock';
import {
  buildApiPath,
  type ApiPath,
  type CallOptions,
  type HttpVerb,
  type Operation,
  type ResponseOf,
} from './endpoints';
import { ApiError, problemToApiError } from './errors';
import type { AuthConfig, Me } from './types';

/**
 * Fetch wrapper for `/api/v1` (docs/PLAN.md §8.1, §12.3, §14.4).
 *
 * - Same-origin cookies only (`credentials: 'same-origin'`), `cache: 'no-store'`.
 * - Mutations carry `X-CSRF-Token`, taken from `GET /me` (`csrf_token`). The token is fetched lazily
 *   and refreshed after a reauthentication, because the server rotates the session (and therefore the
 *   HMAC-derived token) on reauth. Public auth endpoints (login, bootstrap, invitation, reset) carry no
 *   token: the server protects them with its Origin check (api/openapi.yaml, ADR-0031).
 * - Errors are parsed from RFC 9457 problem+json into `ApiError`.
 * - `reauth_required` and `mfa_required` open the registered reauth prompt (ReauthGate) and retry the
 *   request once after the operator re-authenticated.
 * - Any other 401 calls `onUnauthorized` (navigates to /login) unless `authRedirect: false`.
 * - The HTTP `Date` header feeds the server clock offset estimate (HP-UI-011).
 *
 * The client never assumes success: callers only see a resolved promise after a 2xx response.
 */

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export type QueryValue =
  string | number | boolean | null | undefined | readonly (string | number | boolean)[];
export type QueryParams = Record<string, QueryValue>;

/**
 * - `session`: send the per-session CSRF token (default for mutations).
 * - `none`: send no CSRF header (default for GET; public auth endpoints).
 */
export type CsrfMode = 'session' | 'none';

export interface RequestOptions {
  method?: HttpMethod;
  body?: unknown;
  query?: QueryParams;
  signal?: AbortSignal;
  /** Call `onUnauthorized` on 401. Default true. Login/reauth/bootstrap endpoints pass false. */
  authRedirect?: boolean;
  /** Prompt for reauthentication and retry once on `reauth_required`/`mfa_required`. Default true. */
  reauth?: boolean;
  csrf?: CsrfMode;
  /** `Idempotency-Key` for non-idempotent POSTs (HP-API-006). */
  idempotencyKey?: string;
  /** Resource version for optimistic concurrency (`If-Match: "<version>"`). */
  ifMatch?: number;
  /** `blob` returns the success body as a Blob (downloads); errors are still parsed as problem+json. */
  responseType?: 'json' | 'blob';
}

export interface ApiClientHandlers {
  /** Session missing or expired. */
  onUnauthorized: () => void;
  /**
   * Ask the operator to reauthenticate (the error says whether `reauth_required` or `mfa_required`).
   * Resolve true when the server accepted the new authentication.
   */
  onReauthRequired: ((error: ApiError) => Promise<boolean>) | null;
  /** Called after the session was rotated (reauth) and the CSRF token refreshed. */
  onSessionRotated: () => void | Promise<void>;
  onClockSample: (sample: ClockSample) => void;
}

export interface ApiClientConfig {
  baseUrl?: string;
  fetch?: typeof fetch;
  now?: () => number;
}

export function buildQueryString(query: QueryParams | undefined): string {
  if (!query) {
    return '';
  }
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value as readonly (string | number | boolean)[]) {
        params.append(key, String(item));
      }
    } else {
      params.append(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `?${qs}` : '';
}

function isJsonContentType(contentType: string | null): boolean {
  if (!contentType) {
    return false;
  }
  const mime = (contentType.split(';')[0] ?? '').trim().toLowerCase();
  return mime === 'application/json' || mime.endsWith('+json');
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError';
}

export class ApiClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private handlers: ApiClientHandlers;
  private csrfToken: string | null = null;
  private csrfInflight: Promise<string> | null = null;
  private reauthInflight: Promise<boolean> | null = null;

  constructor(config: ApiClientConfig = {}) {
    this.baseUrl = (config.baseUrl ?? '/api/v1').replace(/\/+$/, '');
    this.fetchImpl = config.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.now = config.now ?? (() => Date.now());
    this.handlers = {
      onUnauthorized: () => undefined,
      onReauthRequired: null,
      onSessionRotated: () => undefined,
      onClockSample: recordClockSample,
    };
  }

  /** Installs handlers; returns a function restoring the previous ones. */
  setHandlers(handlers: Partial<ApiClientHandlers>): () => void {
    const previous = this.handlers;
    this.handlers = { ...previous, ...handlers };
    return () => {
      this.handlers = previous;
    };
  }

  setCsrfToken(token: string | null): void {
    this.csrfToken = token;
  }

  /** Forget session-bound state (logout, 401). */
  clearSession(): void {
    this.csrfToken = null;
  }

  request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    return this.send<T>(path, options, false);
  }

  get<T>(path: string, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'GET' });
  }

  post<T>(path: string, body?: unknown, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'POST', body });
  }

  put<T>(path: string, body?: unknown, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'PUT', body });
  }

  patch<T>(path: string, body?: unknown, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'PATCH', body });
  }

  delete<T>(path: string, options: Omit<RequestOptions, 'method' | 'body'> = {}): Promise<T> {
    return this.request<T>(path, { ...options, method: 'DELETE' });
  }

  /**
   * Typed call bound to the OpenAPI contract: `client.call('post', '/api/v1/agents/{id}/keys', { path: { id },
   * body: { public_key } })`. Path, parameters, body and the resolved type all come from `schema.gen.ts`.
   */
  call<M extends HttpVerb, P extends ApiPath<M>>(
    method: M,
    path: P,
    ...[options]: CallOptions<P, M> extends { path: unknown } ? [CallOptions<P, M>] : [CallOptions<P, M>?]
  ): Promise<ResponseOf<Operation<P, M>>> {
    const {
      path: params,
      body,
      query,
      ...rest
    } = (options ?? {}) as {
      path?: Record<string, string | number>;
      body?: unknown;
      query?: QueryParams;
    } & Omit<RequestOptions, 'method' | 'body' | 'query'>;
    return this.request<ResponseOf<Operation<P, M>>>(buildApiPath(path, params), {
      ...rest,
      method: method.toUpperCase() as HttpMethod,
      ...(body !== undefined ? { body } : {}),
      ...(query !== undefined ? { query } : {}),
    });
  }

  /** `GET /me`; also refreshes the CSRF token. */
  async getMe(options: Pick<RequestOptions, 'signal' | 'authRedirect'> = {}): Promise<Me> {
    const me = await this.send<Me>('/me', { ...options, method: 'GET' }, false);
    if (typeof me.csrf_token !== 'string' || me.csrf_token === '') {
      throw new ApiError({
        status: 200,
        code: 'invalid_response',
        detail: 'Session response lacks a CSRF token.',
      });
    }
    this.csrfToken = me.csrf_token;
    return me;
  }

  getAuthConfig(options: Pick<RequestOptions, 'signal'> = {}): Promise<AuthConfig> {
    return this.send<AuthConfig>(
      '/auth/config',
      { ...options, method: 'GET', authRedirect: false, reauth: false },
      false,
    );
  }

  private async ensureCsrfToken(): Promise<string> {
    if (this.csrfToken) {
      return this.csrfToken;
    }
    this.csrfInflight ??= this.getMe()
      .then((me) => me.csrf_token)
      .finally(() => {
        this.csrfInflight = null;
      });
    return this.csrfInflight;
  }

  private runReauth(prompt: (error: ApiError) => Promise<boolean>, error: ApiError): Promise<boolean> {
    // Concurrent requests that hit reauth_required share one prompt.
    this.reauthInflight ??= prompt(error)
      .catch(() => false)
      .finally(() => {
        this.reauthInflight = null;
      });
    return this.reauthInflight;
  }

  private async send<T>(path: string, options: RequestOptions, isRetry: boolean): Promise<T> {
    const method = options.method ?? 'GET';
    const isMutation = method !== 'GET';
    const headers = new Headers({
      Accept: options.responseType === 'blob' ? '*/*' : 'application/json, application/problem+json',
    });

    let body: string | undefined;
    if (options.body !== undefined) {
      headers.set('Content-Type', 'application/json');
      body = JSON.stringify(options.body);
    }

    const csrfMode: CsrfMode = options.csrf ?? (isMutation ? 'session' : 'none');
    if (csrfMode === 'session') {
      headers.set('X-CSRF-Token', await this.ensureCsrfToken());
    }
    if (options.idempotencyKey !== undefined) {
      headers.set('Idempotency-Key', options.idempotencyKey);
    }
    if (options.ifMatch !== undefined) {
      headers.set('If-Match', `"${String(options.ifMatch)}"`);
    }

    const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}${buildQueryString(options.query)}`;
    const sentAt = this.now();
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        ...(body !== undefined ? { body } : {}),
        ...(options.signal ? { signal: options.signal } : {}),
        credentials: 'same-origin',
        cache: 'no-store',
      });
    } catch (error) {
      if (isAbortError(error)) {
        throw error;
      }
      throw new ApiError({ status: 0, code: 'network_error', detail: 'The server could not be reached.' });
    }
    this.recordDate(response, sentAt, this.now());

    if (response.ok) {
      if (options.responseType === 'blob') {
        return (await response.blob()) as T;
      }
      return (await this.readSuccess(response)) as T;
    }

    const error = await this.readError(response);

    if (error.needsReauth && options.reauth !== false && !isRetry && this.handlers.onReauthRequired) {
      const accepted = await this.runReauth(this.handlers.onReauthRequired, error);
      if (!accepted) {
        throw error;
      }
      // The session (and its CSRF token) rotated on reauth.
      this.csrfToken = null;
      await this.getMe();
      await this.handlers.onSessionRotated();
      return this.send<T>(path, options, true);
    }

    if (error.isUnauthenticated) {
      this.clearSession();
      if (options.authRedirect !== false) {
        this.handlers.onUnauthorized();
      }
    }
    throw error;
  }

  private recordDate(response: Response, sentAt: number, receivedAt: number): void {
    const date = response.headers.get('Date');
    if (!date) {
      return;
    }
    const serverTimeMs = Date.parse(date);
    if (Number.isNaN(serverTimeMs)) {
      return;
    }
    this.handlers.onClockSample({ serverTimeMs, sentAt, receivedAt, resolutionMs: 1000 });
  }

  private async readSuccess(response: Response): Promise<unknown> {
    if (response.status === 204 || response.status === 205) {
      return undefined;
    }
    const text = await response.text();
    if (text === '') {
      return undefined;
    }
    if (!isJsonContentType(response.headers.get('Content-Type'))) {
      throw new ApiError({
        status: response.status,
        code: 'invalid_response',
        detail: 'The server returned an unexpected response type.',
      });
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new ApiError({
        status: response.status,
        code: 'invalid_response',
        detail: 'The server returned malformed JSON.',
      });
    }
  }

  private async readError(response: Response): Promise<ApiError> {
    let parsed: unknown = undefined;
    if (isJsonContentType(response.headers.get('Content-Type'))) {
      try {
        parsed = await response.json();
      } catch {
        parsed = undefined;
      }
    }
    return problemToApiError(response.status, parsed);
  }
}

/** Application-wide client. Handlers are installed by `main.tsx` and `ReauthGate`. */
export const api = new ApiClient();
