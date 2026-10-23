import type { Problem, ProblemFieldError } from './types';

export interface ApiErrorInit {
  status: number;
  code: string;
  detail: string;
  title?: string;
  type?: string;
  instance?: string;
  fields?: Record<string, string[]>;
}

/**
 * Typed API failure built from RFC 9457 problem details.
 * `status` is 0 for network failures. `code` is the stable machine-readable string from the server
 * (`forbidden`, `not_found`, `conflict`, `reauth_required`, `mfa_required`, `rate_limited`,
 * `validation_failed`, ...) or a client-side code (`network_error`, `http_<status>`, `invalid_response`).
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly detail: string;
  readonly title: string | undefined;
  readonly type: string | undefined;
  readonly instance: string | undefined;
  /** Field-level validation messages keyed by field name (from `errors[]`). */
  readonly fields: Record<string, string[]>;

  constructor(init: ApiErrorInit) {
    super(init.detail !== '' ? init.detail : (init.title ?? init.code));
    this.name = 'ApiError';
    this.status = init.status;
    this.code = init.code;
    this.detail = init.detail;
    this.title = init.title;
    this.type = init.type;
    this.instance = init.instance;
    this.fields = init.fields ?? {};
  }

  get isReauthRequired(): boolean {
    return this.code === 'reauth_required';
  }

  /** A password session must complete (or repeat) its second factor. */
  get isMfaRequired(): boolean {
    return this.code === 'mfa_required';
  }

  /** The operation needs recent authentication (`reauth_required`) or a recent MFA (`mfa_required`). */
  get needsReauth(): boolean {
    return this.isReauthRequired || this.isMfaRequired;
  }

  /** `If-Match` missing (428) or the resource changed since it was read (409 conflict). */
  get isConflict(): boolean {
    return this.code === 'conflict' || this.code === 'precondition_failed' || this.status === 409;
  }

  get isForbidden(): boolean {
    return this.status === 403 || this.code === 'forbidden';
  }

  /** The session is missing or expired. `reauth_required` and `mfa_required` (also 401) are not. */
  get isUnauthenticated(): boolean {
    return this.status === 401 && !this.needsReauth;
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** Converts a JSON pointer like `/spec/name` into `spec.name`. */
function pointerToField(pointer: string): string {
  return pointer
    .replace(/^#?\//, '')
    .split('/')
    .map((part) => part.replace(/~1/g, '/').replace(/~0/g, '~'))
    .join('.');
}

function normalizeFields(errors: unknown): Record<string, string[]> {
  const fields: Record<string, string[]> = {};
  if (!Array.isArray(errors)) {
    return fields;
  }
  for (const raw of errors as unknown[]) {
    if (typeof raw !== 'object' || raw === null) {
      continue;
    }
    const e = raw as ProblemFieldError;
    const pointer = str(e.pointer);
    const key = str(e.field) ?? (pointer !== undefined ? pointerToField(pointer) : '_');
    const message = str(e.message) ?? str(e.detail) ?? str(e.code) ?? 'Invalid value';
    (fields[key] ??= []).push(message);
  }
  return fields;
}

/** Builds an ApiError from an HTTP status and an (untrusted, possibly malformed) response body. */
export function problemToApiError(status: number, body: unknown): ApiError {
  const p: Problem = typeof body === 'object' && body !== null ? body : {};
  const code = str(p.code) ?? `http_${status}`;
  const title = str(p.title);
  return new ApiError({
    status,
    code,
    detail: str(p.detail) ?? title ?? `Request failed with status ${status}`,
    ...(title !== undefined ? { title } : {}),
    ...(str(p.type) !== undefined ? { type: str(p.type) } : {}),
    ...(str(p.instance) !== undefined ? { instance: str(p.instance) } : {}),
    fields: normalizeFields(p.errors),
  });
}

/** Human-readable message for any thrown value. Never includes response bodies beyond `detail`. */
export function errorMessage(error: unknown): string {
  if (isApiError(error)) {
    return error.detail;
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'Unexpected error';
}
