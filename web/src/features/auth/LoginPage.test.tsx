import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ApiClient } from '../../api/client';
import type { AuthConfig } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { LoginForms, oidcStartUrl } from './LoginPage';

const providers = [{ id: 'corp sso', display_name: 'Corp SSO' }];

function clientReturning(...responses: Response[]) {
  const urls: string[] = [];
  const client = new ApiClient({
    fetch: (input) => {
      urls.push(input instanceof Request ? input.url : input.toString());
      const r = responses.shift();
      return r ? Promise.resolve(r) : Promise.reject(new Error('unexpected request'));
    },
  });
  client.setHandlers({ getPreSessionCsrfToken: () => null });
  return { client, urls };
}

const problem = (status: number, code: string, detail: string) =>
  new Response(JSON.stringify({ status, code, detail }), {
    status,
    headers: { 'Content-Type': 'application/problem+json' },
  });

function renderLogin(config: AuthConfig, client = clientReturning().client, onSignedIn = vi.fn()) {
  renderWithProviders(
    <LoginForms config={config} next="/requests" onSignedIn={onSignedIn} client={client} />,
  );
  return onSignedIn;
}

describe('login modes (HP-UI-006)', () => {
  it('local-only renders the password form and no SSO buttons', () => {
    renderLogin({ local_enabled: true, oidc_providers: [] });
    expect(screen.getByLabelText('Username')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: /single sign-on/i })).not.toBeInTheDocument();
  });

  it('SSO-only renders provider links and no password form', () => {
    renderLogin({ local_enabled: false, oidc_providers: providers });
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
    const link = screen.getByRole('link', { name: 'Sign in with Corp SSO' });
    expect(link).toHaveAttribute('href', '/api/v1/auth/oidc/corp%20sso/start?return_to=%2Frequests');
  });

  it('combined renders both', () => {
    renderLogin({ local_enabled: true, oidc_providers: providers });
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in with Corp SSO' })).toBeInTheDocument();
    expect(screen.getByText('or')).toBeInTheDocument();
  });

  it('explains when no method is enabled', () => {
    renderLogin({ local_enabled: false, oidc_providers: [] });
    expect(screen.getByText('No sign-in method is enabled')).toBeInTheDocument();
  });

  it('moves to the TOTP step on mfa_required and completes after the code is accepted', async () => {
    const user = userEvent.setup();
    const { client, urls } = clientReturning(
      problem(401, 'mfa_required', 'MFA required'),
      new Response(null, { status: 204 }),
    );
    const onSignedIn = renderLogin({ local_enabled: true, oidc_providers: [] }, client);
    await user.type(screen.getByLabelText('Username'), 'ada');
    await user.type(screen.getByLabelText('Password'), 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    const code = await screen.findByLabelText('Authentication code');
    expect(onSignedIn).not.toHaveBeenCalled();
    await user.type(code, '123456');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => {
      expect(onSignedIn).toHaveBeenCalledTimes(1);
    });
    expect(urls).toEqual(['/api/v1/auth/login', '/api/v1/auth/mfa']);
  });

  it('shows the server error and does not sign in on bad credentials', async () => {
    const user = userEvent.setup();
    const { client } = clientReturning(problem(401, 'invalid_credentials', 'Invalid credentials'));
    const onSignedIn = renderLogin({ local_enabled: true, oidc_providers: [] }, client);
    await user.type(screen.getByLabelText('Username'), 'ada');
    await user.type(screen.getByLabelText('Password'), 'wrong password!');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByText('Invalid credentials')).toBeInTheDocument();
    expect(onSignedIn).not.toHaveBeenCalled();
  });
});

describe('oidcStartUrl', () => {
  it('encodes provider id and return path', () => {
    expect(oidcStartUrl({ id: 'a/b', display_name: 'x' }, '/x?y=1')).toBe(
      '/api/v1/auth/oidc/a%2Fb/start?return_to=%2Fx%3Fy%3D1',
    );
  });
});
