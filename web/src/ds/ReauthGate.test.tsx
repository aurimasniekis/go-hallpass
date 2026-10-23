import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ApiClient } from '../api/client';
import { jsonResponse, makeMe, problemResponse } from '../test/fixtures';
import { renderWithProviders } from '../test/utils';
import { ReauthGate } from './ReauthGate';

type Responder = (url: string, init: RequestInit | undefined) => Response;

function scriptedClient(responders: Responder[]) {
  const seen: { url: string; method: string; body: unknown }[] = [];
  const client = new ApiClient({
    fetch: (input, init) => {
      const url = input instanceof Request ? input.url : input.toString();
      seen.push({ url, method: init?.method ?? 'GET', body: init?.body });
      const next = responders.shift();
      if (!next) {
        throw new Error(`unexpected request ${url}`);
      }
      return Promise.resolve(next(url, init));
    },
  });
  client.setCsrfToken('initial');
  return { client, seen };
}

describe('<ReauthGate>', () => {
  it('password session: posts password + code, refreshes CSRF, retries the original request once', async () => {
    const user = userEvent.setup();
    const { client, seen } = scriptedClient([
      () => problemResponse(401, 'reauth_required'),
      () => jsonResponse(200, makeMe()), // prompt inspects the session
      () => jsonResponse(200, makeMe({ csrf: 'rotated' })), // POST /auth/reauth
      () => jsonResponse(200, makeMe({ csrf: 'rotated' })), // client refreshes /me
      () => jsonResponse(200, { lockdown: true }),
    ]);
    renderWithProviders(<ReauthGate client={client} />);

    const pending = client.post('/system/lockdown');
    await user.type(await screen.findByLabelText('Password'), 'correct horse battery');
    await user.type(screen.getByLabelText('Authenticator or recovery code'), ' 123456 ');
    await user.click(screen.getByRole('button', { name: 'Verify' }));

    await expect(pending).resolves.toEqual({ lockdown: true });
    expect(seen.map((s) => `${s.method} ${s.url}`)).toEqual([
      'POST /api/v1/system/lockdown',
      'GET /api/v1/me',
      'POST /api/v1/auth/reauth',
      'GET /api/v1/me',
      'POST /api/v1/system/lockdown',
    ]);
    expect(JSON.parse(String(seen[2]?.body))).toEqual({ password: 'correct horse battery', code: '123456' });
  });

  it('password session without MFA asks only for the password', async () => {
    const { client } = scriptedClient([
      () => problemResponse(401, 'reauth_required'),
      () => jsonResponse(200, makeMe({ operator: { mfa_enrolled: false, mfa_required: false } })),
    ]);
    renderWithProviders(<ReauthGate client={client} />);
    void client.post('/x').catch(() => undefined);
    expect(await screen.findByLabelText('Password')).toBeInTheDocument();
    expect(screen.queryByLabelText('Authenticator or recovery code')).not.toBeInTheDocument();
  });

  it('rejects the original request when the operator cancels', async () => {
    const user = userEvent.setup();
    const { client } = scriptedClient([
      () => problemResponse(401, 'reauth_required'),
      () => jsonResponse(200, makeMe()),
    ]);
    renderWithProviders(<ReauthGate client={client} />);
    const outcome = client.post('/x').catch((e: unknown) => e);
    await screen.findByLabelText('Password');
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    await expect(outcome).resolves.toMatchObject({ code: 'reauth_required' });
  });

  it('SSO session: steps up at the provider with return_to and does not retry', async () => {
    const user = userEvent.setup();
    const navigate = vi.fn();
    const { client, seen } = scriptedClient([
      () => problemResponse(401, 'reauth_required'),
      () => jsonResponse(200, makeMe({ session: { method: 'oidc' } })),
      () =>
        jsonResponse(200, {
          local_login: false,
          bootstrap_required: false,
          providers: [{ slug: 'corp', display_name: 'Corp IdP' }],
        }),
    ]);
    renderWithProviders(
      <ReauthGate client={client} navigate={navigate} currentPath={() => '/servers/s1?tab=roles'} />,
    );
    const outcome = client.post('/credentials/c1/activate').catch((e: unknown) => e);
    await user.click(await screen.findByRole('button', { name: 'Continue with Corp IdP' }));
    expect(navigate).toHaveBeenCalledWith(
      '/auth/oidc/corp/start?purpose=stepup&return_to=%2Fservers%2Fs1%3Ftab%3Droles',
    );
    await expect(outcome).resolves.toMatchObject({ code: 'reauth_required' });
    expect(seen.filter((s) => s.url.includes('/credentials/'))).toHaveLength(1);
  });

  it('SSO session: falls back to TOTP reauth on mfa_required', async () => {
    const user = userEvent.setup();
    const { client, seen } = scriptedClient([
      () => problemResponse(401, 'mfa_required'),
      () => jsonResponse(200, makeMe({ session: { method: 'oidc' } })),
      () =>
        jsonResponse(200, {
          local_login: false,
          bootstrap_required: false,
          providers: [{ slug: 'corp', display_name: 'Corp IdP' }],
        }),
      () => jsonResponse(200, makeMe({ csrf: 'n' })), // POST /auth/reauth/totp
      () => jsonResponse(200, makeMe({ csrf: 'n' })),
      () => jsonResponse(200, { ok: true }),
    ]);
    renderWithProviders(<ReauthGate client={client} />);
    const pending = client.post('/me/recovery-codes');
    await user.click(await screen.findByRole('button', { name: 'Use my authenticator code instead' }));
    await user.type(screen.getByLabelText('Authenticator or recovery code'), '654321');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await expect(pending).resolves.toEqual({ ok: true });
    expect(seen[3]?.url).toBe('/api/v1/auth/reauth/totp');
    expect(JSON.parse(String(seen[3]?.body))).toEqual({ code: '654321' });
  });

  it('limited session is sent to finish signing in', async () => {
    const user = userEvent.setup();
    const navigate = vi.fn();
    const { client } = scriptedClient([
      () => problemResponse(401, 'mfa_required'),
      () => jsonResponse(200, makeMe({ session: { limited: true } })),
    ]);
    renderWithProviders(<ReauthGate client={client} navigate={navigate} currentPath={() => '/agents'} />);
    const outcome = client.get('/agents').catch((e: unknown) => e);
    await user.click(await screen.findByRole('button', { name: 'Go to sign-in' }));
    await waitFor(() => {
      expect(navigate).toHaveBeenCalledWith('/login?next=%2Fagents');
    });
    await expect(outcome).resolves.toMatchObject({ code: 'mfa_required' });
  });
});
