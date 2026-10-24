import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ApiClient } from '../../api/client';
import type { AuthConfig } from '../../api/types';
import { jsonResponse, makeMe, problemResponse } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { LoginForms, resumeStep } from './LoginPage';
import { oidcStartUrl, ssoErrorMessage } from './sso';

const providers = [{ slug: 'corp-sso', display_name: 'Corp SSO' }];

function config(local: boolean, p = providers): AuthConfig {
  return { local_login: local, providers: p, bootstrap_required: false };
}

function clientReturning(...responses: Response[]) {
  const calls: { url: string; init: RequestInit | undefined }[] = [];
  const client = new ApiClient({
    fetch: (input, init) => {
      calls.push({ url: input instanceof Request ? input.url : input.toString(), init });
      const r = responses.shift();
      return r ? Promise.resolve(r) : Promise.reject(new Error('unexpected request'));
    },
  });
  return { client, calls };
}

function renderLogin(
  cfg: AuthConfig,
  client = clientReturning().client,
  onSignedIn = vi.fn(),
  extra: { ssoError?: string } = {},
) {
  renderWithProviders(
    <LoginForms
      config={cfg}
      next="/requests"
      onSignedIn={onSignedIn}
      client={client}
      ssoError={extra.ssoError}
    />,
  );
  return onSignedIn;
}

describe('login modes (HP-UI-006)', () => {
  it('local-only renders the password form and no SSO buttons', () => {
    renderLogin(config(true, []));
    expect(screen.getByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: /single sign-on/i })).not.toBeInTheDocument();
  });

  it('SSO-only renders provider links (browser navigation to /auth/oidc) and no password form', () => {
    renderLogin(config(false));
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Sign in with Corp SSO' });
    expect(link).toHaveAttribute('href', '/auth/oidc/corp-sso/start?purpose=login&return_to=%2Frequests');
  });

  it('combined renders both', () => {
    renderLogin(config(true));
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in with Corp SSO' })).toBeInTheDocument();
    expect(screen.getByText('or')).toBeInTheDocument();
  });

  it('explains when no method is enabled', () => {
    renderLogin(config(false, []));
    expect(screen.getByText('No sign-in method is enabled')).toBeInTheDocument();
  });

  it('shows SSO errors from ?sso_error without exposing internals', () => {
    renderLogin(config(true), undefined, undefined, { ssoError: 'forbidden' });
    expect(screen.getByText(ssoErrorMessage('forbidden'))).toBeInTheDocument();
  });

  it('login → mfa_pending → code accepted; CSRF from me.csrf_token is sent on /auth/mfa', async () => {
    const user = userEvent.setup();
    const { client, calls } = clientReturning(
      jsonResponse(200, { mfa_pending: true, must_enroll: false, me: makeMe({ csrf: 'limited-csrf' }) }),
      jsonResponse(200, makeMe({ csrf: 'full' })),
    );
    const onSignedIn = renderLogin(config(true, []), client);
    await user.type(screen.getByLabelText('Email'), 'ada@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    const code = await screen.findByLabelText('Authentication code');
    expect(onSignedIn).not.toHaveBeenCalled();
    await user.type(code, '123456');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => {
      expect(onSignedIn).toHaveBeenCalledTimes(1);
    });
    expect(calls.map((c) => c.url)).toEqual(['/api/v1/auth/login', '/api/v1/auth/mfa']);
    expect(JSON.parse(calls[0]?.init?.body as string)).toEqual({
      email: 'ada@example.test',
      password: 'correct horse battery',
    });
    expect(new Headers(calls[0]?.init?.headers).has('X-CSRF-Token')).toBe(false);
    expect(new Headers(calls[1]?.init?.headers).get('X-CSRF-Token')).toBe('limited-csrf');
  });

  it('login → must_enroll starts TOTP enrollment', async () => {
    const user = userEvent.setup();
    const { client, calls } = clientReturning(
      jsonResponse(200, { mfa_pending: false, must_enroll: true, me: makeMe({ csrf: 'c' }) }),
      jsonResponse(200, {
        secret: 'JBSWY3DPEHPK3PXP',
        uri: 'otpauth://totp/HallPass:ada?secret=JBSWY3DPEHPK3PXP',
      }),
    );
    renderLogin(config(true, []), client);
    await user.type(screen.getByLabelText('Email'), 'ada@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('Set up two-factor authentication')).toBeInTheDocument();
    expect(await screen.findByDisplayValue('JBSWY3DPEHPK3PXP')).toBeInTheDocument();
    expect(calls[1]?.url).toBe('/api/v1/me/mfa/totp');
  });

  it('login without MFA signs in directly', async () => {
    const user = userEvent.setup();
    const { client } = clientReturning(
      jsonResponse(200, { mfa_pending: false, must_enroll: false, me: makeMe() }),
    );
    const onSignedIn = renderLogin(config(true, []), client);
    await user.type(screen.getByLabelText('Email'), 'ada@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    await waitFor(() => {
      expect(onSignedIn).toHaveBeenCalledTimes(1);
    });
  });

  it('shows the server error and does not sign in on bad credentials', async () => {
    const user = userEvent.setup();
    const { client } = clientReturning(problemResponse(401, 'invalid_credentials', 'Invalid credentials'));
    const onSignedIn = renderLogin(config(true, []), client);
    await user.type(screen.getByLabelText('Email'), 'ada@example.test');
    await user.type(screen.getByLabelText('Password'), 'wrong password!');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('Invalid credentials')).toBeInTheDocument();
    expect(onSignedIn).not.toHaveBeenCalled();
  });
});

describe('resumeStep', () => {
  it('resumes limited sessions at MFA or enrollment and full sessions as done', () => {
    expect(resumeStep(undefined, undefined)).toBeNull();
    expect(resumeStep(makeMe({ session: { limited: true } }), undefined)).toBe('mfa');
    expect(resumeStep(makeMe({ session: { limited: true, needs_enroll: true } }), undefined)).toBe('enroll');
    expect(resumeStep(makeMe(), undefined)).toBe('done');
  });

  it('offers the TOTP fallback after an SSO step-up reported mfa_required', () => {
    expect(resumeStep(makeMe({ session: { method: 'oidc' } }), 'mfa_required')).toBe('stepup-totp');
    expect(
      resumeStep(makeMe({ session: { method: 'oidc' }, operator: { mfa_enrolled: false } }), 'mfa_required'),
    ).toBeNull();
    // Any other SSO error keeps the operator on the sign-in page to read it.
    expect(resumeStep(makeMe(), 'forbidden')).toBeNull();
  });
});

describe('oidcStartUrl', () => {
  it('encodes the provider slug, purpose and a validated return path', () => {
    expect(oidcStartUrl('a/b', 'login', '/x?y=1')).toBe(
      '/auth/oidc/a%2Fb/start?purpose=login&return_to=%2Fx%3Fy%3D1',
    );
    expect(oidcStartUrl('corp', 'stepup', 'https://evil.example/')).toBe(
      '/auth/oidc/corp/start?purpose=stepup&return_to=%2F',
    );
    expect(oidcStartUrl('corp', 'link', undefined, { linkToken: 't' })).toBe(
      '/auth/oidc/corp/start?purpose=link&link_token=t',
    );
  });
});
