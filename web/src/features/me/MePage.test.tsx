import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Me } from '../../api/types';
import { makeMe } from '../../test/fixtures';
import { json, mockApi, renderAppAt, type Call } from '../operators/testing';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function meRoutes(me: Me, extra: Record<string, (c: Call) => Response> = {}) {
  return {
    'GET /api/v1/me': () => json(200, me),
    'GET /api/v1/me/sessions': () =>
      json(200, {
        items: [
          {
            id: 'ws_1',
            auth_method: 'password',
            created_at: '2026-01-01T00:00:00Z',
            last_seen_at: '2026-01-01T00:00:00Z',
            expires_at: '2026-01-02T00:00:00Z',
            ip: '192.0.2.1',
            user_agent: 'ExampleBrowser/1.0',
            current: true,
          },
          {
            id: 'ws_2',
            auth_method: 'password',
            created_at: '2026-01-01T00:00:00Z',
            last_seen_at: '2026-01-01T00:00:00Z',
            expires_at: '2026-01-02T00:00:00Z',
            ip: '192.0.2.2',
            user_agent: 'Chrome',
            current: false,
          },
        ],
      }),
    'GET /api/v1/me/identities': () => json(200, { items: [] }),
    'GET /api/v1/me/provider-links': () => json(200, { items: [] }),
    'GET /api/v1/auth/config': () =>
      json(200, {
        local_login: true,
        bootstrap_required: false,
        providers: [{ slug: 'corp', display_name: 'Corp' }],
      }),
    ...extra,
  };
}

describe('My account page', () => {
  it('renders profile, sessions, password and SSO link options', async () => {
    mockApi(meRoutes(makeMe()));
    renderAppAt('/me');
    expect(await screen.findByRole('heading', { level: 1, name: 'My account' })).toBeInTheDocument();
    expect(screen.getByText('Signed in with')).toBeInTheDocument();
    expect(await screen.findByText('This session')).toBeInTheDocument();
    expect(screen.getByRole('form', { name: 'Change password' })).toBeInTheDocument();
    expect(await screen.findByRole('button', { name: 'Link Corp' })).toBeInTheDocument();
  });

  it('hides password change for accounts without a local password', async () => {
    mockApi(meRoutes(makeMe({ operator: { has_password: false } })));
    renderAppAt('/me');
    await screen.findByRole('heading', { level: 1, name: 'My account' });
    expect(screen.queryByRole('form', { name: 'Change password' })).not.toBeInTheDocument();
  });

  it('revokes another session with DELETE /me/sessions/{id}', async () => {
    const user = userEvent.setup();
    const calls = mockApi(
      meRoutes(makeMe(), { 'DELETE /api/v1/me/sessions/ws_2': () => new Response(null, { status: 204 }) }),
    );
    renderAppAt('/me');
    await user.click(await screen.findByRole('button', { name: 'Revoke' }));
    const dialog = (await screen.findByText('That browser is signed out immediately.')).closest<HTMLElement>(
      '[role="dialog"]',
    );
    if (!dialog) {
      throw new Error('confirmation dialog not found');
    }
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'DELETE' && c.url === '/api/v1/me/sessions/ws_2')).toBe(true);
    });
  });

  it('does not offer disabling two-factor when it is required', async () => {
    mockApi(meRoutes(makeMe({ operator: { mfa_enrolled: true, mfa_required: true } })));
    renderAppAt('/me');
    expect(await screen.findByRole('button', { name: 'Disable two-factor' })).toBeDisabled();
    expect(screen.getByText(/required for your account and cannot be disabled/)).toBeInTheDocument();
  });

  it('regenerates recovery codes and shows them once', async () => {
    const user = userEvent.setup();
    mockApi(
      meRoutes(makeMe(), {
        'POST /api/v1/me/recovery-codes': () => json(200, { codes: ['aaaa-bbbb', 'cccc-dddd'] }),
      }),
    );
    renderAppAt('/me');
    await user.click(await screen.findByRole('button', { name: 'Regenerate recovery codes' }));
    await user.click(await screen.findByRole('button', { name: 'Regenerate' }));
    expect(await screen.findByText('aaaa-bbbb')).toBeInTheDocument();
    expect(screen.getByText('cccc-dddd')).toBeInTheDocument();
  });

  it('creates a Slack link code and shows the exact command', async () => {
    const user = userEvent.setup();
    const calls = mockApi(
      meRoutes(makeMe(), {
        'POST /api/v1/me/provider-link-codes': () =>
          json(200, { code: 'K7Q2ZP', expires_at: new Date(Date.now() + 600_000).toISOString() }),
      }),
    );
    renderAppAt('/me');
    await user.click(await screen.findByRole('button', { name: 'Create Slack link code' }));
    expect(await screen.findByDisplayValue('/hallpass link K7Q2ZP')).toBeInTheDocument();
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ provider: 'slack' });
  });

  it('offers authenticator setup when not enrolled', async () => {
    mockApi(meRoutes(makeMe({ operator: { mfa_enrolled: false, mfa_required: false } })));
    renderAppAt('/me');
    expect(await screen.findByRole('button', { name: 'Set up authenticator' })).toBeInTheDocument();
  });
});
