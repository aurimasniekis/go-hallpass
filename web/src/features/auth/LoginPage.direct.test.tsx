import { screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { renderWithProviders } from '../../test/utils';
import { LoginPage } from './LoginPage';
import { clearSignedOut, markSignedOut } from './sso';

function json(status: number, body: unknown, type = 'application/json'): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': type } });
}

function serve(config: Record<string, unknown>) {
  vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.startsWith('/api/v1/me')) {
      return Promise.resolve(json(401, { status: 401, code: 'unauthenticated' }, 'application/problem+json'));
    }
    if (url.startsWith('/api/v1/auth/config')) {
      return Promise.resolve(json(200, config));
    }
    return Promise.reject(new Error(`unexpected ${url}`));
  });
}

const withDirect = {
  local_login: true,
  bootstrap_required: false,
  providers: [{ slug: 'corp', display_name: 'Corp SSO' }],
  direct_provider: 'corp',
};

function renderPage(props: { direct?: boolean; ssoError?: string } = {}) {
  const redirect = vi.fn();
  renderWithProviders(
    <LoginPage
      next="/requests"
      onSignedIn={vi.fn()}
      direct={props.direct ?? true}
      ssoError={props.ssoError}
      redirect={redirect}
    />,
  );
  return redirect;
}

describe('sign-in page with a default SSO provider', () => {
  beforeEach(clearSignedOut);
  afterEach(() => {
    vi.restoreAllMocks();
    clearSignedOut();
  });

  it('continues to the provider and offers the email and password page', async () => {
    serve(withDirect);
    const redirect = renderPage();
    expect(await screen.findByText('Continuing to Corp SSO…')).toBeInTheDocument();
    expect(redirect).toHaveBeenCalledWith('/auth/oidc/corp/start?purpose=login&return_to=%2Frequests');
    expect(screen.getByRole('link', { name: 'Sign in with email and password' })).toHaveAttribute(
      'href',
      '/login/password?next=%2Frequests',
    );
  });

  it('shows every sign-in method on the fallback page', async () => {
    serve(withDirect);
    const redirect = renderPage({ direct: false });
    expect(await screen.findByLabelText('Password')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Sign in with Corp SSO' })).toBeInTheDocument();
    expect(redirect).not.toHaveBeenCalled();
  });

  it('stays on the page after a failed SSO sign-in', async () => {
    serve(withDirect);
    const redirect = renderPage({ ssoError: 'forbidden' });
    expect(await screen.findByText(/Single sign-on was refused/)).toBeInTheDocument();
    expect(redirect).not.toHaveBeenCalled();
  });

  it('stays on the page right after signing out', async () => {
    markSignedOut();
    serve(withDirect);
    const redirect = renderPage();
    expect(await screen.findByText('You are signed out.')).toBeInTheDocument();
    expect(screen.getByLabelText('Password')).toBeInTheDocument();
    expect(redirect).not.toHaveBeenCalled();
  });

  it('ignores a default provider that is not offered', async () => {
    serve({ ...withDirect, providers: [] });
    const redirect = renderPage();
    expect(await screen.findByLabelText('Password')).toBeInTheDocument();
    expect(redirect).not.toHaveBeenCalled();
  });
});
