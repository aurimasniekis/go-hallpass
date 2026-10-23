import { safeNextPath } from './redirect';

/**
 * Browser navigation into the OIDC flow (`GET /auth/oidc/{slug}/start`, outside `/api`). These are full
 * page loads, not fetches: the provider round trip sets and checks a binding cookie (HP-OIDC-002).
 * Errors come back as `/login?sso_error=<code>`; a test login returns to
 * `/settings/auth?test_login=<provider_id>` and the preview is fetched from the API.
 */
export type OidcPurpose = 'login' | 'stepup' | 'test' | 'link';

export function oidcStartUrl(
  slug: string,
  purpose: OidcPurpose,
  returnTo?: string,
  extra: { linkToken?: string } = {},
): string {
  const params = new URLSearchParams();
  params.set('purpose', purpose);
  if (returnTo !== undefined) {
    params.set('return_to', safeNextPath(returnTo));
  }
  if (extra.linkToken) {
    params.set('link_token', extra.linkToken);
  }
  return `/auth/oidc/${encodeURIComponent(slug)}/start?${params.toString()}`;
}

/** Messages for `sso_error` codes (stable codes from the server, never internals). */
export function ssoErrorMessage(code: string): string {
  switch (code) {
    case 'mfa_required':
      return 'Your identity provider could not prove a fresh sign-in. Confirm with your Hallpass authenticator code.';
    case 'forbidden':
      return 'Single sign-on was refused for this account. Ask an administrator to check the provider mapping or your account status.';
    case 'not_found':
      return 'That sign-in provider is not available.';
    case 'precondition_failed':
    case 'precondition_required':
      return 'Single sign-on could not continue (for example, step-up needs an SSO session). Start again.';
    case 'rate_limited':
      return 'Too many sign-in attempts. Wait a minute and try again.';
    case 'unauthorized':
    case 'invalid_state':
      return 'The sign-in attempt expired or was already used. Start again.';
    default:
      return 'Single sign-on failed. Try again, or contact an administrator.';
  }
}

const STEPUP_RETURN_KEY = 'hallpass.stepup.return';

/**
 * Remembers where an SSO step-up started. If the provider cannot prove a fresh login the server sends
 * the browser to `/login?sso_error=mfa_required`, and the TOTP fallback returns here afterwards.
 * Only a validated same-origin path is stored (sessionStorage; nothing sensitive).
 */
export function rememberStepUpReturn(path: string): void {
  try {
    window.sessionStorage.setItem(STEPUP_RETURN_KEY, safeNextPath(path));
  } catch {
    // Not persisted; the fallback returns to the dashboard.
  }
}

export function takeStepUpReturn(): string {
  try {
    const value = window.sessionStorage.getItem(STEPUP_RETURN_KEY);
    window.sessionStorage.removeItem(STEPUP_RETURN_KEY);
    return safeNextPath(value);
  } catch {
    return '/';
  }
}
