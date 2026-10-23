/**
 * Hand-written API types (WP19 foundation).
 *
 * These are a minimal stand-in until `api/openapi.yaml` exists and `openapi-typescript` generates
 * `web/src/api/schema.d.ts` (docs/PLAN.md §8.1). Types marked PROVISIONAL describe request/response
 * shapes the backend has not specified yet; they must be reconciled with the OpenAPI spec.
 */

export interface OidcProviderSummary {
  id: string;
  display_name: string;
}

/** `GET /api/v1/auth/config` (public). */
export interface AuthConfig {
  local_enabled: boolean;
  oidc_providers: OidcProviderSummary[];
}

/** `GET /api/v1/me`. */
export interface Me {
  operator_id: string;
  display_name: string;
  roles: string[];
  permissions: string[];
  /** Per-session CSRF token to send as `X-CSRF-Token` on mutations (docs/PLAN.md §12.3). */
  csrf_token: string;
  /** RFC 3339 time of the last primary authentication. */
  auth_time: string;
  /** RFC 3339 time of the last MFA verification. */
  mfa_at?: string;
}

/** One entry of the RFC 9457 `errors[]` extension. PROVISIONAL: the field naming is not yet fixed. */
export interface ProblemFieldError {
  field?: string;
  pointer?: string;
  code?: string;
  detail?: string;
  message?: string;
}

/** RFC 9457 problem details (`application/problem+json`), docs/PLAN.md §8.1. */
export interface Problem {
  type?: string;
  title?: string;
  status?: number;
  code?: string;
  detail?: string;
  instance?: string;
  errors?: ProblemFieldError[];
}

/** Cursor page envelope used by list endpoints. */
export interface Page<T> {
  items: T[];
  next_cursor?: string | null;
}

/** Live event payload (docs/PLAN.md §8.3). `summary` carries only non-sensitive fields. */
export interface LiveEvent {
  type: string;
  resource: string;
  resource_id?: string;
  version?: number;
  at?: string;
  summary?: Record<string, unknown>;
}

/** PROVISIONAL `POST /auth/login` body. */
export interface LoginRequest {
  username: string;
  password: string;
}

/** PROVISIONAL `POST /auth/login` success body. A `mfa_required` problem is also accepted. */
export interface LoginResponse {
  mfa_required?: boolean;
}

/** PROVISIONAL `POST /auth/mfa` body (TOTP code or recovery code). */
export interface MfaRequest {
  code: string;
}

/** PROVISIONAL `POST /auth/reauth` body. */
export interface ReauthRequest {
  password: string;
  totp_code?: string;
}

/** PROVISIONAL `POST /auth/bootstrap` body. */
export interface BootstrapRequest {
  token: string;
  username: string;
  display_name: string;
  password: string;
}
