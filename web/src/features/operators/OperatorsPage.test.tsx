import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { makeMe, makeOperator } from '../../test/fixtures';
import { json, mockApi, renderAppAt } from './testing';

const ADMIN_PERMS = ['operators.manage', 'dashboard.view'];

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('Operators page', () => {
  it('lists operators with roles, status and two-factor state', async () => {
    mockApi({
      'GET /api/v1/me': () => json(200, makeMe({ permissions: ADMIN_PERMS })),
      'GET /api/v1/operators': () =>
        json(200, {
          items: [
            makeOperator({ id: 'op_1', display_name: 'Ada' }),
            makeOperator({
              id: 'op_2',
              display_name: 'Bob',
              email: 'bob@example.test',
              roles: ['approver'],
              enabled: false,
              mfa_enrolled: false,
              mfa_required: true,
            }),
          ],
        }),
    });
    renderAppAt('/operators');
    const table = await screen.findByRole('region', { name: 'Operators' });
    const bob = await within(table).findByRole('link', { name: 'Bob' });
    expect(bob).toHaveAttribute('href', '/operators/op_2');
    const row = bob.closest('tr');
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getByText('Approver')).toBeInTheDocument();
    expect(within(row as HTMLElement).getByText('Disabled')).toBeInTheDocument();
    expect(within(row as HTMLElement).getByText('Required, not enrolled')).toBeInTheDocument();
  });

  it('lists pending invitations without tokens and revokes one (HP-AUTH-011)', async () => {
    const user = userEvent.setup();
    let revoked = false;
    const calls = mockApi({
      'GET /api/v1/me': () => json(200, makeMe({ permissions: ADMIN_PERMS })),
      'GET /api/v1/operators': () => json(200, { items: [] }),
      'GET /api/v1/invitations': () =>
        json(200, {
          items: revoked
            ? []
            : [
                {
                  id: 'ab12',
                  email: 'new@example.test',
                  roles: ['viewer'],
                  expires_at: '2026-10-27T00:00:00Z',
                  created_at: '2026-10-24T00:00:00Z',
                  created_by: 'operator:opr_1',
                },
              ],
        }),
      'DELETE /api/v1/invitations/ab12': () => {
        revoked = true;
        return new Response(null, { status: 204 });
      },
    });
    renderAppAt('/operators');
    const card = await screen.findByRole('region', { name: 'Pending invitations' });
    expect(await within(card).findByText('new@example.test')).toBeInTheDocument();
    await user.click(within(card).getByRole('button', { name: 'Revoke invitation for new@example.test' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Revoke' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'DELETE' && c.url === '/api/v1/invitations/ab12')).toBe(true);
    });
    expect(await within(card).findByText('No pending invitations')).toBeInTheDocument();
  });

  it('shows permission denied without operators.manage and never fetches the list', async () => {
    const calls = mockApi({
      'GET /api/v1/me': () => json(200, makeMe({ permissions: ['dashboard.view'] })),
    });
    renderAppAt('/operators');
    expect(await screen.findByText("You don't have access")).toBeInTheDocument();
    expect(calls.some((c) => c.url.startsWith('/api/v1/operators'))).toBe(false);
  });

  it('creates an invitation with an idempotency key and shows the link once', async () => {
    const user = userEvent.setup();
    const calls = mockApi({
      'GET /api/v1/me': () => json(200, makeMe({ permissions: ADMIN_PERMS })),
      'GET /api/v1/operators': () => json(200, { items: [] }),
      'POST /api/v1/invitations': () =>
        json(200, { token: 'inv-token', expires_at: '2026-01-04T00:00:00Z', url: '/invite/inv-token' }),
    });
    renderAppAt('/operators');
    await user.click(await screen.findByRole('button', { name: /Invite/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Invite operator' });
    await user.type(within(dialog).getByLabelText('Email'), 'new@example.test');
    await user.click(within(dialog).getByRole('button', { name: 'Create invitation' }));

    await waitFor(() => {
      expect(calls.map((c) => `${c.method} ${c.url}`)).toContain('POST /api/v1/invitations');
    });
    // antd's ids are deterministic in tests ('test-id'), so dialogs are located by content, not name.
    const link = await screen.findByText(`${window.location.origin}/invite/inv-token`);
    const secret = link.closest<HTMLElement>('[role="dialog"]');
    if (!secret) {
      throw new Error('one-time secret dialog not found');
    }
    expect(within(secret).getByText('Shown only once')).toBeInTheDocument();
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.body).toEqual({ email: 'new@example.test', roles: ['viewer'] });
    expect(post?.headers.get('Idempotency-Key')).toBeTruthy();
    expect(post?.headers.get('X-CSRF-Token')).toBe('csrf-test');
    const done = within(secret).getByRole('button', { name: 'Done' });
    expect(done).toBeDisabled();
    await user.click(within(secret).getByRole('checkbox', { name: 'I have stored this securely' }));
    expect(done).toBeEnabled();
  });

  it('creates an operator and explains that a reset link is needed', async () => {
    const user = userEvent.setup();
    const calls = mockApi({
      'GET /api/v1/me': () => json(200, makeMe({ permissions: ADMIN_PERMS })),
      'GET /api/v1/operators': () => json(200, { items: [] }),
      'POST /api/v1/operators': () => json(201, makeOperator({ id: 'op_9', display_name: 'Cleo' })),
    });
    renderAppAt('/operators');
    await user.click(await screen.findByRole('button', { name: /Create operator/ }));
    const dialog = await screen.findByRole('dialog', { name: 'Create operator' });
    await user.type(within(dialog).getByLabelText('Email'), 'cleo@example.test');
    await user.type(within(dialog).getByLabelText('Display name'), 'Cleo');
    await user.click(within(dialog).getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('Created Cleo')).toBeInTheDocument();
    await waitFor(() => {
      expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
        email: 'cleo@example.test',
        display_name: 'Cleo',
        roles: ['viewer'],
        mfa_required: true,
      });
    });
  });
});
