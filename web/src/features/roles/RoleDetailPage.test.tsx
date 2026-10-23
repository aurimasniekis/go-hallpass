import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { LoginCredential, Role } from '../../api/types';
import { jsonResponse } from '../../test/fixtures';
import { renderInventory, ts } from '../servers/testApp';

const role: Role = {
  id: 'role_1',
  server_id: 'srv_1',
  alias: 'deploy',
  remote_user: 'deploy',
  capabilities: ['exec'],
  default_duration: 5400,
  max_duration: 86400,
  recording_mode: 'mandatory',
  enabled: true,
  version: 3,
};

const failed: LoginCredential = {
  id: 'cred_1',
  role_id: 'role_1',
  kind: 'key',
  algorithm: 'ssh-ed25519',
  public_key: 'ssh-ed25519 AAAA',
  fingerprint: 'SHA256:cred',
  state: 'pending',
  probe_error: 'permission denied (publickey)',
  created_at: ts,
  authorized_keys_line: 'restrict,from="192.0.2.1" ssh-ed25519 AAAA hallpass',
};

const baseHandlers = [
  ['GET', '/api/v1/roles/role_1', () => jsonResponse(200, role)],
  ['GET', '/api/v1/servers', () => jsonResponse(200, { items: [] })],
] as const;

describe('role detail', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('explains the missing permission instead of showing credentials', async () => {
    renderInventory('/roles/role_1', { permissions: ['inventory.read'], handlers: [...baseHandlers] });
    expect(await screen.findByRole('heading', { level: 1, name: 'Role deploy' })).toBeInTheDocument();
    expect(screen.getByText('1h 30m')).toBeInTheDocument();
    expect(await screen.findByText(/needs the credentials.manage permission/)).toBeInTheDocument();
  });

  it('after a failed probe offers only forced activation, behind a typed confirmation', async () => {
    const user = userEvent.setup();
    const { calls } = renderInventory('/roles/role_1', {
      permissions: ['inventory.read', 'credentials.manage'],
      handlers: [
        ...baseHandlers,
        ['GET', '/api/v1/roles/role_1/credentials', () => jsonResponse(200, { items: [failed] })],
        ['GET', '/api/v1/user-cas', () => jsonResponse(200, { items: [] })],
        [
          'POST',
          '/api/v1/credentials/cred_1/activate',
          () => jsonResponse(200, { ...failed, state: 'active' }),
        ],
      ],
    });
    expect(await screen.findByText('permission denied (publickey)')).toBeInTheDocument();
    expect(screen.getByDisplayValue(failed.authorized_keys_line)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Activate' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Force activate' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('The destination has not accepted this key')).toBeInTheDocument();
    const confirm = within(dialog).getByRole('button', { name: 'Force activate' });
    expect(confirm).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/to confirm/), 'FORCE');
    await user.click(confirm);
    await waitFor(() => {
      expect(calls.some((c) => c.url === '/api/v1/credentials/cred_1/activate?force=true')).toBe(true);
    });
  });
});
