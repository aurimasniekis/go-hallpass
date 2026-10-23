import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { SSHBan } from '../../api/types';
import { makeMe } from '../../test/fixtures';
import { mockApi, on, renderInRouter } from '../requests/testHelpers';
import { SshBansCard } from './SshBans';

afterEach(() => {
  vi.restoreAllMocks();
});

const soon = new Date(Date.now() + 90 * 60_000).toISOString();
const bans: SSHBan[] = [
  {
    id: 'ban_1',
    address: '203.0.113.7',
    failures: 12,
    reason: 'too many failed SSH authentications',
    offense: 2,
    banned_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    expires_at: soon,
  },
  {
    id: 'ban_2',
    address: '2001:db8:1:2::/64',
    failures: 30,
    reason: 'too many failed SSH connections',
    banned_at: new Date(Date.now() - 60_000).toISOString(),
    expires_at: soon,
  },
];

describe('<SshBansCard>', () => {
  it('lists bans with a countdown and lifts one after confirmation', async () => {
    const user = userEvent.setup();
    const seen = mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['system.read', 'system.settings'] })),
      on('GET', '/api/v1/ssh-bans', { items: bans }),
      (req) =>
        req.method === 'DELETE' && req.url === '/api/v1/ssh-bans/ban_1'
          ? new Response(null, { status: 204 })
          : undefined,
    );
    renderInRouter(<SshBansCard />);
    expect(await screen.findByText('203.0.113.7')).toBeInTheDocument();
    expect(screen.getByText('2001:db8:1:2::/64')).toBeInTheDocument();
    expect(screen.getByText('#2')).toBeInTheDocument();
    expect(screen.getByText('too many failed SSH authentications')).toBeInTheDocument();
    expect(screen.getAllByRole('timer')[0]).toHaveTextContent(/1h 29m|1h 30m|89m|90m/);

    await user.click(screen.getByRole('button', { name: 'Lift ban on 203.0.113.7' }));
    const dialog = await screen.findByRole('dialog');
    expect(seen.some((r) => r.method === 'DELETE')).toBe(false);
    await user.click(within(dialog).getByRole('button', { name: 'Lift ban' }));
    await waitFor(() => {
      expect(seen.some((r) => r.method === 'DELETE' && r.url === '/api/v1/ssh-bans/ban_1')).toBe(true);
    });
    expect(await screen.findByText('Ban on 203.0.113.7 lifted.')).toBeInTheDocument();
  });

  it('hides the lift action without system.settings', async () => {
    mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['system.read'] })),
      on('GET', '/api/v1/ssh-bans', { items: bans }),
    );
    renderInRouter(<SshBansCard />);
    expect(await screen.findByText('203.0.113.7')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Lift/ })).not.toBeInTheDocument();
  });

  it('shows an empty state and a permission state', async () => {
    mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['system.read'] })),
      on('GET', '/api/v1/ssh-bans', { items: [] }),
    );
    renderInRouter(<SshBansCard />);
    expect(await screen.findByText('No active bans')).toBeInTheDocument();
  });

  it('does not request bans without system.read', async () => {
    const seen = mockApi(on('GET', '/api/v1/me', makeMe({ permissions: ['dashboard.view'] })));
    renderInRouter(<SshBansCard />);
    expect(await screen.findByText(/needs the system.read permission/)).toBeInTheDocument();
    expect(seen.some((r) => r.url.startsWith('/api/v1/ssh-bans'))).toBe(false);
  });
});
