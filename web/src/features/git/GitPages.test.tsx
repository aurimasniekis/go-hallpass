import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { mockApi } from '../policy/mockApi';
import { renderInventory } from '../servers/testApp';
import { GitProfiles } from './GitProfiles';

const base = {
  enabled: true,
  groups: [],
  labels: {},
  version: 1,
  created_at: '2026-10-24T08:00:00Z',
  updated_at: '2026-10-24T08:00:00Z',
  address_redacted: false,
  port: 22,
};

const profile = {
  id: 'rol_1',
  server_id: 'srv_git',
  alias: 'acme-push',
  description: 'Agent branches',
  remote_user: 'git',
  capabilities: ['git-read', 'git-write'],
  default_duration: 3600,
  max_duration: 28800,
  recording_mode: 'mandatory',
  enabled: true,
  version: 4,
  git: { repos: ['acme/{api,web}'], push: { branches: ['agent/**'], protected_branches: ['main'] } },
};

describe('Git pages', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists only git remotes and creates one from a preset', async () => {
    const user = userEvent.setup();
    const { calls, router } = renderInventory('/git', {
      permissions: ['inventory.read', 'inventory.write', 'inventory.address.read'],
      handlers: [
        [
          'GET',
          '/api/v1/servers',
          () =>
            jsonResponse(200, {
              items: [
                {
                  ...base,
                  id: 'srv_git',
                  kind: 'git',
                  alias: 'github',
                  display_name: 'github',
                  address: 'github.com',
                },
                {
                  ...base,
                  id: 'srv_ssh',
                  kind: 'ssh',
                  alias: 'web1',
                  display_name: 'web1',
                  address: '10.0.0.1',
                },
              ],
            }),
        ],
        [
          'POST',
          '/api/v1/servers',
          (c) => jsonResponse(201, { ...base, ...(c.body as object), id: 'srv_new' }),
        ],
        [
          'GET',
          /\/api\/v1\/servers\/srv_new/,
          () =>
            jsonResponse(200, {
              ...base,
              id: 'srv_new',
              kind: 'git',
              alias: 'gitlab',
              display_name: 'gitlab',
              address: 'gitlab.com',
            }),
        ],
        [
          'GET',
          /\/api\/v1\/(host-identities|servers\/srv_new\/(host-identities|roles))/,
          () => jsonResponse(200, { items: [] }),
        ],
      ],
    });
    expect(await screen.findByRole('link', { name: 'github' })).toBeInTheDocument();
    const table = screen.getByRole('table');
    expect(within(table).getByText('GitHub')).toBeInTheDocument();
    expect(within(table).queryByText('web1')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /New git remote/ }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByText('GitLab.com'));
    expect(within(dialog).getByLabelText('Name')).toHaveValue('gitlab');
    await user.click(within(dialog).getByRole('button', { name: 'Create git remote' }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/git/srv_new');
    });
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({
      kind: 'git',
      alias: 'gitlab',
      description: '',
      address: 'gitlab.com',
      port: 22,
    });
  });

  it('shows profiles and edits push rules with brace patterns intact', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['inventory.read', 'inventory.write'] }),
      'GET /api/v1/servers/srv_git/roles': { items: [profile] },
      'PATCH /api/v1/roles/rol_1': (c) =>
        jsonResponse(200, { ...profile, ...(c.body as object), version: 5 }),
    });
    renderWithProviders(<GitProfiles serverId="srv_git" canWrite keyHint="Add it as a deploy key." />);
    expect(await screen.findByText('acme/{api,web}')).toBeInTheDocument();
    expect(screen.getByText('Branches: agent/** · Protected: main')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Edit acme-push' }));
    const dialog = await screen.findByRole('dialog');
    await user.type(
      within(dialog).getByRole('combobox', { name: 'Repositories' }),
      'team-{{a,b}/infra{Enter}',
    );
    await user.click(within(dialog).getByRole('button', { name: 'Save profile' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PATCH')).toBe(true);
    });
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.headers.get('If-Match')).toBe('"4"');
    expect((patch?.body as { git: { repos: string[] } }).git.repos).toEqual([
      'acme/{api,web}',
      'team-{a,b}/infra',
    ]);
    expect((patch?.body as { capabilities: string[] }).capabilities).toEqual(['git-read', 'git-write']);
  });

  it('disables and deletes an access profile after confirmation', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['inventory.read', 'inventory.write'] }),
      'GET /api/v1/servers/srv_git/roles': { items: [profile] },
      'POST /api/v1/roles/rol_1/disable': { ...profile, enabled: false },
      'DELETE /api/v1/roles/rol_1': () => new Response(null, { status: 204 }),
    });
    renderWithProviders(<GitProfiles serverId="srv_git" canWrite keyHint="Add it as a deploy key." />);
    await user.click(await screen.findByRole('button', { name: 'Disable acme-push' }));
    const disable = await screen.findByRole('dialog', { name: 'Disable access profile acme-push' });
    expect(within(disable).getByText(/pending requests are canceled/)).toBeInTheDocument();
    await user.click(within(disable).getByRole('button', { name: 'Disable' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST' && c.path.endsWith('/roles/rol_1/disable'))).toBe(true);
    });

    await user.click(screen.getByRole('button', { name: 'Delete acme-push' }));
    // Dialogs share a generated title id in tests, so find this one by its text.
    const del = (await screen.findByText(/login keys are revoked/)).closest<HTMLElement>('[role="dialog"]');
    if (!del) {
      throw new Error('no delete dialog');
    }
    expect(within(del).getByText(/cannot be undone/)).toBeInTheDocument();
    await user.click(within(del).getByRole('button', { name: 'Delete access profile' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'DELETE' && c.path.endsWith('/roles/rol_1'))).toBe(true);
    });
  });

  it('shows the bare public key to add on the git host', async () => {
    const user = userEvent.setup();
    mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['inventory.read', 'inventory.write'] }),
      'GET /api/v1/servers/srv_git/roles': { items: [profile] },
      'GET /api/v1/roles/rol_1/credentials': {
        items: [
          {
            id: 'lcr_1',
            role_id: 'rol_1',
            kind: 'managed_key',
            algorithm: 'ssh-ed25519',
            public_key: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample',
            fingerprint: 'SHA256:example',
            state: 'pending',
            created_at: '2026-10-24T08:00:00Z',
            created_by: 'operator:opr_1',
            authorized_keys_line:
              'restrict,from="192.0.2.10" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample hallpass:github/acme-push',
          },
        ],
      },
    });
    renderWithProviders(<GitProfiles serverId="srv_git" canWrite keyHint="Add it as a deploy key." />);
    await user.click(await screen.findByRole('button', { name: /expand row/i }));
    expect(await screen.findByLabelText('Public key')).toHaveValue(
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample hallpass:github/acme-push',
    );
    expect(screen.queryByLabelText('authorized_keys line')).not.toBeInTheDocument();
  });
});
