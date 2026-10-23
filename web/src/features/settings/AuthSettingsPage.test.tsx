import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { api } from '../../api/client';
import { jsonResponse, makeMe } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { AuthSettingsPage, claimsText } from './AuthSettingsPage';

const provider = {
  id: 'oidc_1',
  slug: 'corp',
  display_name: 'Corp IdP',
  issuer: 'https://idp.example.test',
  client_id: 'hallpass',
  has_client_secret: true,
  scopes: ['openid'],
  provisioning: 'preprovisioned',
  enabled: true,
  version: 2,
  test_login_ok_at: null,
  redirect_uri: 'https://hallpass.example.test/auth/oidc/callback',
};

function mockApi(overrides: Record<string, () => Response> = {}) {
  const calls: { method: string; url: string; body: unknown }[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ method, url, body: init?.body ? JSON.parse(init.body as string) : undefined });
    const key = `${method} ${url.split('?')[0] ?? url}`;
    const override = overrides[key];
    if (override) {
      return Promise.resolve(override());
    }
    if (url.startsWith('/api/v1/me')) {
      return Promise.resolve(jsonResponse(200, makeMe({ permissions: ['auth.settings'] })));
    }
    if (key === 'GET /api/v1/settings/auth') {
      return Promise.resolve(jsonResponse(200, { local_login_disabled: false }));
    }
    if (key === 'GET /api/v1/oidc-providers') {
      return Promise.resolve(jsonResponse(200, { items: [provider] }));
    }
    if (key === 'GET /api/v1/oidc-providers/oidc_1/mappings') {
      return Promise.resolve(jsonResponse(200, { items: [] }));
    }
    return Promise.reject(new Error(`unexpected ${key}`));
  });
  return calls;
}

describe('<AuthSettingsPage>', () => {
  afterEach(() => {
    api.clearSession();
  });

  it('lists providers, shows the copyable redirect URI and starts a test login by navigation', async () => {
    const user = userEvent.setup();
    mockApi();
    const navigate = vi.fn();
    renderWithProviders(<AuthSettingsPage navigate={navigate} />);
    expect(await screen.findByRole('heading', { level: 1, name: 'Authentication' })).toBeInTheDocument();
    const table = await screen.findByRole('region', { name: 'SSO providers' });
    expect(within(table).getByText('Corp IdP')).toBeInTheDocument();
    expect(within(table).getByText('Never')).toBeInTheDocument();
    await user.click(within(table).getByRole('button', { name: 'Details' }));
    expect(screen.getByDisplayValue(provider.redirect_uri)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Run test login' }));
    expect(navigate).toHaveBeenCalledWith('/auth/oidc/corp/start?purpose=test&return_to=%2Fsettings%2Fauth');
  });

  it('requires the typed phrase before enforcing SSO-only', async () => {
    const user = userEvent.setup();
    const calls = mockApi({
      'PUT /api/v1/settings/auth': () => jsonResponse(200, { local_login_disabled: true }),
    });
    renderWithProviders(<AuthSettingsPage />);
    await user.click(await screen.findByRole('button', { name: 'Disable password sign-in (SSO only)' }));
    const confirm = await screen.findByRole('button', { name: 'Disable password sign-in' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText(/to confirm/), 'SSO ONLY');
    await user.click(confirm);
    await waitFor(() => {
      expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({ local_login_disabled: true });
    });
  });

  it('shows the test-login preview with claims as inert text', async () => {
    mockApi({
      'GET /api/v1/oidc-providers/oidc_1/test-login': () =>
        jsonResponse(200, {
          claims: { name: '<img src=x onerror=alert(1)>', note: 'a‮b' },
          would_provision: false,
          provision_reason: 'not linked',
          mapped_roles: ['approver'],
          mapped_groups: [],
          effective_roles: ['approver'],
        }),
    });
    renderWithProviders(<AuthSettingsPage testLoginProviderId="oidc_1" />);
    expect(await screen.findByText('The provider authenticated you')).toBeInTheDocument();
    const pre = screen.getByLabelText('Claims JSON');
    expect(pre.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(pre.querySelector('img')).toBeNull();
    expect(pre.textContent).toContain('<U+202E>');
  });

  it('claimsText reveals bidi controls', () => {
    expect(claimsText({ a: '‮' })).toContain('<U+202E>');
  });

  it('shows permission denied without auth.settings', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(jsonResponse(200, makeMe({ permissions: [] })));
    renderWithProviders(<AuthSettingsPage />);
    expect(await screen.findByText("You don't have access")).toBeInTheDocument();
  });
});
