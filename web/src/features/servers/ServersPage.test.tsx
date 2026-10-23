import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { HostIdentity, Role, Server } from '../../api/types';
import { jsonResponse } from '../../test/fixtures';
import { renderInventory, ts } from './testApp';

const visible: Server = {
  id: 'srv_1',
  alias: 'db1',
  display_name: 'Database',
  enabled: true,
  groups: [],
  labels: {},
  version: 5,
  created_at: ts,
  updated_at: ts,
  address_redacted: false,
  address: '10.0.0.5',
  port: 22,
  active_host_identities: 1,
};
const redacted: Server = { ...visible, address_redacted: true, address: '', port: 0 };

const role: Role = {
  id: 'role_1',
  server_id: 'srv_1',
  alias: 'deploy',
  remote_user: 'deploy',
  capabilities: ['exec', 'shell'],
  default_duration: 1800,
  max_duration: 21600,
  recording_mode: 'mandatory',
  record_input: true,
  approval_channels: ['web'],
  enabled: true,
  version: 1,
};

const pending: HostIdentity = {
  id: 'hid_1',
  server_id: 'srv_1',
  algorithm: 'ssh-ed25519',
  public_key: 'ssh-ed25519 AAAA',
  fingerprint: 'SHA256:hostkey',
  state: 'pending',
  enrolled_via: 'scan',
  created_at: ts,
};

describe('servers pages', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows addresses only when the API returns them (HP-SRV-010)', async () => {
    renderInventory('/servers', {
      permissions: ['inventory.read'],
      handlers: [
        [
          'GET',
          '/api/v1/servers',
          () => jsonResponse(200, { items: [visible, { ...redacted, id: 'srv_2', alias: 'db2' }] }),
        ],
      ],
    });
    expect(await screen.findByText('10.0.0.5:22')).toBeInTheDocument();
    expect(screen.getByText('Hidden')).toBeInTheDocument();
  });

  it('edit of a redacted server never sends address fields', async () => {
    const user = userEvent.setup();
    const { calls } = renderInventory('/servers/srv_1', {
      permissions: ['inventory.read', 'inventory.write'],
      handlers: [
        ['GET', '/api/v1/servers/srv_1', () => jsonResponse(200, redacted)],
        ['PATCH', '/api/v1/servers/srv_1', () => jsonResponse(200, redacted)],
      ],
    });
    expect(await screen.findByText('Descriptions and labels are informational')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText('The address is hidden')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PATCH')).toBe(true);
    });
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.body).not.toHaveProperty('address');
    expect(patch?.body).not.toHaveProperty('port');
    expect(patch?.headers.get('If-Match')).toBe('"5"');
  });

  it('roles tab shows durations human-readably and warns about input recording', async () => {
    renderInventory('/servers/srv_1?tab=roles', {
      permissions: ['inventory.read'],
      handlers: [
        ['GET', '/api/v1/servers/srv_1', () => jsonResponse(200, visible)],
        ['GET', '/api/v1/servers/srv_1/roles', () => jsonResponse(200, { items: [role] })],
      ],
    });
    expect(await screen.findByRole('link', { name: 'deploy' })).toHaveAttribute('href', '/roles/role_1');
    expect(screen.getByText('30m')).toBeInTheDocument();
    expect(screen.getByText('6h')).toBeInTheDocument();
    expect(screen.getByText('input recorded')).toBeInTheDocument();
  });

  it('host identities need inventory.address.read', async () => {
    renderInventory('/servers/srv_1?tab=identities', {
      permissions: ['inventory.read', 'inventory.write'],
      handlers: [['GET', '/api/v1/servers/srv_1', () => jsonResponse(200, redacted)]],
    });
    expect(await screen.findByText(/need the inventory.address.read permission/)).toBeInTheDocument();
  });

  it('scans host keys and confirms a pending identity after showing its fingerprint', async () => {
    const user = userEvent.setup();
    let identities: HostIdentity[] = [];
    const { calls } = renderInventory('/servers/srv_1?tab=identities', {
      permissions: ['inventory.read', 'inventory.write', 'inventory.address.read'],
      handlers: [
        ['GET', '/api/v1/servers/srv_1', () => jsonResponse(200, visible)],
        ['GET', '/api/v1/servers/srv_1/host-identities', () => jsonResponse(200, { items: identities })],
        [
          'POST',
          '/api/v1/servers/srv_1/host-identities:scan',
          () => {
            identities = [pending];
            return jsonResponse(200, { items: [pending] });
          },
        ],
        [
          'POST',
          '/api/v1/host-identities/hid_1/confirm',
          () => jsonResponse(200, { ...pending, state: 'active' }),
        ],
      ],
    });
    expect(await screen.findByText('No host identities')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Scan host keys/ }));
    expect(await screen.findByText(/pending confirmation/)).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Confirm' }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(/out of band/)).toBeInTheDocument();
    expect(within(dialog).getByText('SHA256:hostkey')).toBeInTheDocument();
    await user.click(within(dialog).getByRole('button', { name: /Fingerprint matches/ }));
    await waitFor(() => {
      expect(calls.some((c) => c.url === '/api/v1/host-identities/hid_1/confirm')).toBe(true);
    });
  });

  it('destination collectors are labeled unverified and revocation sends a reason with an idempotency key', async () => {
    const user = userEvent.setup();
    const collector = {
      id: 'dc_1',
      server_id: 'srv_1',
      name: 'auditd',
      public_key: 'ssh-ed25519 AAAA',
      fingerprint: 'SHA256:collector',
      state: 'active',
      last_seq: 42,
      created_at: ts,
      created_by: 'op_1',
    };
    const { calls } = renderInventory('/servers/srv_1?tab=collectors', {
      permissions: ['inventory.read', 'credentials.manage'],
      handlers: [
        ['GET', '/api/v1/servers/srv_1', () => jsonResponse(200, visible)],
        ['GET', '/api/v1/destination-collectors', () => jsonResponse(200, { items: [collector] })],
        [
          'POST',
          '/api/v1/destination-collectors/dc_1/revoke',
          () => jsonResponse(200, { ...collector, state: 'revoked' }),
        ],
      ],
    });
    expect(await screen.findByText('Destination-reported, not verified')).toBeInTheDocument();
    expect(await screen.findByText('auditd')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Revoke' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText(/Reason/), 'host rebuilt');
    await user.click(within(dialog).getByRole('button', { name: 'Revoke collector' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST')).toBe(true);
    });
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.body).toEqual({ reason: 'host rebuilt' });
    expect(post?.headers.get('Idempotency-Key')).toBeTruthy();
    expect(calls.some((c) => c.url === '/api/v1/destination-collectors?server_id=srv_1')).toBe(true);
  });
});
