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
});
