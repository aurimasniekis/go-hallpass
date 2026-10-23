import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Operator } from '../../api/types';
import { makeMe, makeOperator } from '../../test/fixtures';
import { json, mockApi, renderAppAt, type Call } from './testing';

const PERMS = ['operators.manage', 'dashboard.view'];

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

function detailRoutes(op: Operator, extra: Record<string, (c: Call) => Response> = {}) {
  return {
    'GET /api/v1/me': () => json(200, makeMe({ permissions: PERMS })),
    [`GET /api/v1/operators/${op.id}`]: () => json(200, op),
    [`GET /api/v1/operators/${op.id}/sessions`]: () =>
      json(200, {
        items: [
          {
            id: 'ws_9',
            auth_method: 'password',
            created_at: '2026-01-01T00:00:00Z',
            last_seen_at: '2026-01-01T01:00:00Z',
            expires_at: '2026-01-02T00:00:00Z',
            ip: '192.0.2.10',
            user_agent: 'Agent‮evil',
            current: false,
          },
        ],
      }),
    [`GET /api/v1/operators/${op.id}/identities`]: () => json(200, { items: [] }),
    [`GET /api/v1/operators/${op.id}/provider-links`]: () => json(200, { items: [] }),
    ...extra,
  };
}

const bob = makeOperator({
  id: 'op_2',
  display_name: 'Bob',
  email: 'bob@example.test',
  roles: ['approver', 'administrator'],
  role_assignments: [
    { role: 'approver', source: 'manual' },
    { role: 'administrator', source: 'sso', source_ref: 'hp-admins' },
  ],
  groups: ['oncall'],
});

describe('Operator detail page', () => {
  it('shows profile, SSO-managed roles read-only and reveals hidden characters in user agents', async () => {
    mockApi(detailRoutes(bob));
    renderAppAt('/operators/op_2');
    expect(await screen.findByRole('heading', { level: 1, name: 'Bob' })).toBeInTheDocument();
    const ssoList = await screen.findByRole('list', { name: 'Roles managed by SSO' });
    expect(within(ssoList).getByText(/Administrator/)).toBeInTheDocument();
    expect(await screen.findByText('Agent<U+202E>evil')).toBeInTheDocument();
  });

  it('saves only changed fields when editing roles', async () => {
    const user = userEvent.setup();
    const calls = mockApi(
      detailRoutes(bob, {
        'PATCH /api/v1/operators/op_2': () =>
          json(200, { ...bob, roles: ['approver', 'administrator', 'auditor'] }),
      }),
    );
    renderAppAt('/operators/op_2');
    const form = await screen.findByRole('form', { name: 'Roles and groups' });
    await user.click(within(form).getByLabelText('Manual roles'));
    await user.click(await screen.findByText(/^Auditor —/));
    await user.click(within(form).getByRole('button', { name: 'Save access' }));
    await waitFor(() => {
      expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ roles: ['approver', 'auditor'] });
    });
  });

  it('cannot disable your own account', async () => {
    const self = makeOperator({ id: 'op_1', display_name: 'Ada' });
    mockApi(detailRoutes(self));
    renderAppAt('/operators/op_1');
    expect(await screen.findByText('This is your account')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Disable' })).toBeDisabled();
  });

  it('issues a reset link after confirmation and shows it once', async () => {
    const user = userEvent.setup();
    const calls = mockApi(
      detailRoutes(bob, {
        'POST /api/v1/operators/op_2/reset-token': () =>
          json(200, { token: 'rst', expires_at: '2026-01-01T01:00:00Z', url: '/reset/rst' }),
      }),
    );
    renderAppAt('/operators/op_2');
    await user.click(await screen.findByRole('button', { name: 'Issue reset link' }));
    await user.click(await screen.findByRole('button', { name: 'Issue link' }));
    expect(await screen.findByText(`${window.location.origin}/reset/rst`)).toBeInTheDocument();
    expect(calls.filter((c) => c.method === 'POST')).toHaveLength(1);
  });

  it('requires typing the email to disable another operator', async () => {
    const user = userEvent.setup();
    const calls = mockApi(
      detailRoutes(bob, {
        'PATCH /api/v1/operators/op_2': () => json(200, { ...bob, enabled: false }),
      }),
    );
    renderAppAt('/operators/op_2');
    await user.click(await screen.findByRole('button', { name: 'Disable' }));
    const confirm = await screen.findByRole('button', { name: 'Disable operator' });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText(/to confirm/), 'bob@example.test');
    await user.click(confirm);
    await waitFor(() => {
      expect(calls.find((c) => c.method === 'PATCH')?.body).toEqual({ enabled: false });
    });
  });
});
