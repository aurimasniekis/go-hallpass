import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe } from '../../test/fixtures';
import { mockApi } from '../policy/mockApi';
import { renderInRouter } from '../requests/testHelpers';
import { ApiTokensPage } from './ApiTokensPage';

const token = {
  id: 'atk_1',
  name: 'terraform',
  operator_id: 'opr_1',
  role: 'administrator',
  hint: 'Wxyz',
  created_at: '2026-10-24T08:00:00Z',
  expires_at: '2099-01-01T00:00:00Z',
  never_expires: false,
};

describe('<ApiTokensPage>', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('creates a token, shows it once, and revokes it', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['operators.manage'], operator: { roles: ['administrator'] } }),
      'GET /api/v1/api-tokens': { items: [token] },
      'GET /api/v1/operators': { items: [] },
      'POST /api/v1/api-tokens': () =>
        jsonResponse(201, {
          token: 'hallpass_at_secretsecret',
          api_token: { ...token, id: 'atk_2', name: 'ci' },
        }),
      'DELETE /api/v1/api-tokens/atk_1': { ...token, revoked_at: '2026-10-24T09:00:00Z' },
    });
    renderInRouter(<ApiTokensPage />);
    expect(await screen.findByText('hallpass_at_…Wxyz')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /New token/ }));
    const form = await screen.findByRole('form', { name: 'New API token' });
    await user.type(within(form).getByLabelText('Name'), 'ci');
    await user.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText('hallpass_at_secretsecret')).toBeInTheDocument();
    await user.click(screen.getByRole('checkbox', { name: 'I have stored this securely' }));
    await user.click(screen.getByRole('button', { name: 'Done' }));
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.body).toEqual({ name: 'ci', role: 'administrator', expires_in_days: 90 });
    expect(post?.headers.get('Idempotency-Key')).toBeTruthy();

    await user.click(screen.getByRole('button', { name: 'Revoke token terraform' }));
    const dialog = (await screen.findByText(/stops working immediately/)).closest<HTMLElement>(
      '[role="dialog"]',
    );
    if (!dialog) {
      throw new Error('no revoke dialog');
    }
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'DELETE')).toBe(true);
    });
  });

  it('issues a token that never expires, with a warning and no expiry', async () => {
    const user = userEvent.setup();
    const forever = { ...token, id: 'atk_3', name: 'tf', expires_at: undefined, never_expires: true };
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['operators.manage'], operator: { roles: ['administrator'] } }),
      'GET /api/v1/api-tokens': { items: [forever] },
      'GET /api/v1/operators': { items: [] },
      'POST /api/v1/api-tokens': () =>
        jsonResponse(201, { token: 'hallpass_at_forever', api_token: forever }),
    });
    renderInRouter(<ApiTokensPage />);
    // Expires and Last used both read "Never".
    expect(await screen.findAllByText('Never')).toHaveLength(2);

    await user.click(screen.getByRole('button', { name: /New token/ }));
    const form = await screen.findByRole('form', { name: 'New API token' });
    await user.type(within(form).getByLabelText('Name'), 'tf');
    await user.click(within(form).getByRole('switch', { name: 'Never expires' }));
    expect(await within(form).findByText('A token that never expires')).toBeInTheDocument();
    expect(within(form).queryByLabelText('Expires after (days)')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText('hallpass_at_forever')).toBeInTheDocument();
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.body).toEqual({ name: 'tf', role: 'administrator', never_expires: true });
  });

  it('lets an administrator pick any role and names the token that issued a child', async () => {
    const user = userEvent.setup();
    const child = { ...token, id: 'atk_4', name: 'deed', role: 'auditor', parent_token_id: 'atk_1' };
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['operators.manage'], operator: { roles: ['administrator'] } }),
      'GET /api/v1/api-tokens': { items: [token, child] },
      'GET /api/v1/operators': { items: [] },
      'POST /api/v1/api-tokens': () => jsonResponse(201, { token: 'hallpass_at_audit', api_token: child }),
    });
    renderInRouter(<ApiTokensPage />);
    expect(await screen.findByText('Issued by token terraform')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /New token/ }));
    const form = await screen.findByRole('form', { name: 'New API token' });
    await user.type(within(form).getByLabelText('Name'), 'deed');
    await user.click(within(form).getByLabelText('Role'));
    await user.click(await screen.findByTitle('Auditor'));
    await user.click(screen.getByRole('button', { name: 'Create token' }));
    expect(await screen.findByText('hallpass_at_audit')).toBeInTheDocument();
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.body).toEqual({ name: 'deed', role: 'auditor', expires_in_days: 90 });
  });
});
