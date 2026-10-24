import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ApiClient } from '../../api/client';
import { jsonResponse, makeMe } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { AFTER_ENROLL_INTRO, LoginForms } from './LoginPage';
import { RecoverPage } from './RecoverPage';

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

const enrollment = { secret: 'JBSWY3DPEHPK3PXP', uri: 'otpauth://totp/Hallpass:ada?secret=JBSWY3DPEHPK3PXP' };

describe('break-glass recovery page (HP-AUTH-016, SR-07)', () => {
  it('redeems the token only on confirmation and offers the password reset link', async () => {
    const user = userEvent.setup();
    const { client, calls } = clientReturning(
      jsonResponse(200, {
        must_enroll: false,
        password_reset: { token: 'rst', expires_at: '2026-10-24T13:00:00Z', url: '/reset/rst' },
        me: makeMe({ csrf: 'bg-csrf' }),
      }),
    );
    const onDone = vi.fn();
    const onResetPassword = vi.fn();
    renderWithProviders(
      <RecoverPage initialToken="tok-1" onDone={onDone} onResetPassword={onResetPassword} client={client} />,
    );
    expect(calls).toHaveLength(0); // nothing is redeemed on page load
    await user.click(screen.getByRole('button', { name: 'Use recovery login' }));
    expect(await screen.findByText('Signed in for recovery')).toBeInTheDocument();
    expect(calls[0]?.url).toBe('/api/v1/auth/recover');
    expect(calls[0]?.init?.body).toBe(JSON.stringify({ token: 'tok-1' }));
    expect(new Headers(calls[0]?.init?.headers).has('X-CSRF-Token')).toBe(false);
    await user.click(screen.getByRole('button', { name: 'Set password' }));
    expect(onResetPassword).toHaveBeenCalledWith('/reset/rst');
    await user.click(screen.getByRole('button', { name: 'Continue to Hallpass' }));
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it('requires a new authenticator when the session must enroll', async () => {
    const user = userEvent.setup();
    const { client, calls } = clientReturning(
      jsonResponse(200, { must_enroll: true, password_reset: null, me: makeMe({ csrf: 'bg' }) }),
      jsonResponse(200, enrollment),
    );
    renderWithProviders(
      <RecoverPage initialToken="tok" onDone={vi.fn()} onResetPassword={vi.fn()} client={client} />,
    );
    await user.click(screen.getByRole('button', { name: 'Use recovery login' }));
    expect(await screen.findByText('Set up a new authenticator')).toBeInTheDocument();
    expect(await screen.findByDisplayValue('JBSWY3DPEHPK3PXP')).toBeInTheDocument();
    expect(calls[1]?.url).toBe('/api/v1/me/mfa/totp');
    expect(screen.queryByRole('button', { name: 'Continue to Hallpass' })).not.toBeInTheDocument();
  });
});

describe('enrollment does not complete sign-in (SR-03)', () => {
  it('asks for a later code after enrollment, then signs in', async () => {
    const user = userEvent.setup();
    const { client, calls } = clientReturning(
      jsonResponse(200, { mfa_pending: false, must_enroll: true, me: makeMe({ csrf: 'c' }) }),
      jsonResponse(200, enrollment),
      jsonResponse(200, { codes: ['aaaa-bbbb'] }),
      jsonResponse(200, makeMe({ csrf: 'limited' })), // GET /me after the CSRF token was cleared
      jsonResponse(200, makeMe({ csrf: 'full' })), // POST /auth/mfa
    );
    const onSignedIn = vi.fn();
    renderWithProviders(
      <LoginForms
        config={{ local_login: true, providers: [], bootstrap_required: false }}
        next="/"
        onSignedIn={onSignedIn}
        client={client}
      />,
    );
    await user.type(screen.getByLabelText('Email'), 'ada@example.test');
    await user.type(screen.getByLabelText('Password'), 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));
    await user.type(await screen.findByLabelText('Code from your app'), '123456');
    await user.click(screen.getByRole('button', { name: 'Confirm' }));
    await screen.findByRole('dialog', { name: 'Recovery codes' });
    await user.click(screen.getByRole('checkbox', { name: 'I have stored this securely' }));
    await user.click(screen.getByRole('button', { name: 'Done' }));
    expect(await screen.findByText(AFTER_ENROLL_INTRO)).toBeInTheDocument();
    expect(onSignedIn).not.toHaveBeenCalled();
    await user.type(screen.getByLabelText('Authentication code'), '654321');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => {
      expect(onSignedIn).toHaveBeenCalledTimes(1);
    });
    expect(calls[2]?.url).toBe('/api/v1/me/mfa/totp/confirm');
    expect(calls.at(-1)?.url).toBe('/api/v1/auth/mfa');
  });
});
