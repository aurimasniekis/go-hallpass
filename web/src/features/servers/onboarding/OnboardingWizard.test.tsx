import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { LoginCredential, Role, Server } from '../../../api/types';
import { jsonResponse, makeMe } from '../../../test/fixtures';
import { mockApi, on, renderInRouter } from '../../requests/testHelpers';
import { OnboardingWizard } from './OnboardingWizard';

afterEach(() => {
  vi.restoreAllMocks();
});

const ts = '2026-06-01T10:00:00Z';
const ALL = [
  'inventory.read',
  'inventory.write',
  'inventory.address.read',
  'credentials.manage',
  'policy.read',
  'policy.write',
];

const server: Server = {
  id: 'srv_1',
  alias: 'web1',
  display_name: 'web1',
  enabled: true,
  groups: [],
  labels: {},
  version: 1,
  created_at: ts,
  updated_at: ts,
  address_redacted: false,
  address: '10.0.0.5',
  port: 22,
  active_host_identities: 1,
};
const role: Role = {
  id: 'rol_1',
  server_id: 'srv_1',
  alias: 'deploy',
  remote_user: 'deploy',
  capabilities: ['exec', 'shell'],
  default_duration: 1800,
  max_duration: 7200,
  recording_mode: 'mandatory',
  approval_channels: ['web'],
  enabled: true,
  version: 1,
};
const pendingCred: LoginCredential = {
  id: 'crd_1',
  role_id: 'rol_1',
  kind: 'generated',
  algorithm: 'ssh-ed25519',
  public_key: 'ssh-ed25519 AAAA',
  fingerprint: 'SHA256:cred',
  state: 'pending',
  created_at: ts,
  authorized_keys_line: 'from="192.0.2.1",restrict ssh-ed25519 AAAA hallpass',
};

describe('<OnboardingWizard>', () => {
  it('creates the server and moves to the host identity step', async () => {
    const user = userEvent.setup();
    const onNavigate = vi.fn();
    const seen = mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ALL })),
      on('POST', '/api/v1/servers', server, 201),
      on('GET', '/api/v1/servers', { items: [] }),
    );
    renderInRouter(<OnboardingWizard location={{}} onNavigate={onNavigate} />);
    await user.type(await screen.findByLabelText('Alias'), 'web1');
    await user.type(screen.getByLabelText('Address'), '10.0.0.5');
    await user.click(screen.getByRole('button', { name: 'Create server and continue' }));
    await waitFor(() => {
      expect(onNavigate).toHaveBeenCalledWith({ server: 'srv_1', step: 'identity' });
    });
    const post = seen.find((r) => r.method === 'POST');
    expect(post?.body).toMatchObject({ alias: 'web1', address: '10.0.0.5', port: 22 });
    expect(post?.headers.get('Idempotency-Key')).toMatch(/.+/);
  });

  it('resumes at the credentials step, shows the install command and tests the login', async () => {
    const user = userEvent.setup();
    let cred = pendingCred;
    const seen = mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ALL })),
      on('GET', '/api/v1/servers/srv_1', server),
      on('GET', '/api/v1/servers/srv_1/host-identities', {
        items: [
          {
            id: 'hid_1',
            server_id: 'srv_1',
            algorithm: 'ssh-ed25519',
            public_key: 'k',
            fingerprint: 'SHA256:h',
            state: 'active',
            enrolled_via: 'scan',
            created_at: ts,
          },
        ],
      }),
      on('GET', '/api/v1/servers/srv_1/roles', { items: [role] }),
      on('GET', '/api/v1/policy/rules', { items: [] }),
      (req) =>
        req.method === 'GET' && req.url === '/api/v1/roles/rol_1/credentials'
          ? jsonResponse(200, { items: [cred] })
          : undefined,
      (req) => {
        if (req.method === 'POST' && req.url === '/api/v1/credentials/crd_1/probe') {
          cred = { ...cred, probe_error: 'ssh: unable to authenticate' };
          return jsonResponse(200, cred);
        }
        return undefined;
      },
    );
    renderInRouter(<OnboardingWizard location={{ server: 'srv_1' }} onNavigate={() => undefined} />);
    expect(await screen.findByText('4. Login credentials')).toBeInTheDocument();
    expect(
      screen.getByText(
        `echo 'from="192.0.2.1",restrict ssh-ed25519 AAAA hallpass' | sudo tee -a ~deploy/.ssh/authorized_keys`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Activate' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Test login' }));
    expect(await screen.findByText('The destination did not accept the key')).toBeInTheDocument();
    expect(screen.getByText('ssh: unable to authenticate')).toBeInTheDocument();
    expect(await screen.findByText('Test login again')).toBeInTheDocument();
    expect(seen.filter((r) => r.url === '/api/v1/credentials/crd_1/probe')).toHaveLength(1);
  });

  it('refuses without inventory.write', async () => {
    mockApi(on('GET', '/api/v1/me', makeMe({ permissions: ['inventory.read'] })));
    renderInRouter(<OnboardingWizard location={{}} onNavigate={() => undefined} />);
    expect(
      await screen.findByText(/needs the inventory.read and inventory.write permissions/),
    ).toBeInTheDocument();
  });
});
