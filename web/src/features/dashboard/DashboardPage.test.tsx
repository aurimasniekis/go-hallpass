import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { SystemStatus } from '../../api/types';
import { makeMe } from '../../test/fixtures';
import { mockApi, on, renderInRouter } from '../requests/testHelpers';
import { DashboardPage } from './DashboardPage';
import { LockdownBanner } from './LockdownControls';

afterEach(() => {
  vi.restoreAllMocks();
});

function status(overrides: Partial<SystemStatus> = {}): SystemStatus {
  return {
    lockdown: false,
    version: '1.2.3',
    boot_id: 'b1',
    pending_requests: 2,
    active_grants: 5,
    live_channels: 1,
    storage_ok: true,
    policy_version: 7,
    breakglass_alert: false,
    ...overrides,
  };
}

const zeroStats = {
  range: '24h',
  bucket_seconds: 3600,
  requests_by_state: {},
  requests: [{ t: '2026-01-01T00:00:00Z', n: 0 }],
  sessions: [{ t: '2026-01-01T00:00:00Z', n: 0 }],
};

describe('<DashboardPage>', () => {
  it('shows real status counts and empty charts honestly, and enables lockdown with typed confirmation', async () => {
    const user = userEvent.setup();
    let locked = false;
    const seen = mockApi(
      on(
        'GET',
        '/api/v1/me',
        makeMe({
          permissions: ['dashboard.view', 'requests.read', 'sessions.read', 'system.lockdown.enable'],
        }),
      ),
      (req) => {
        if (req.method === 'POST' && req.url === '/api/v1/system/lockdown') {
          locked = true;
        }
        return undefined;
      },
      (req) => on(req.method, '/api/v1/system/status', status({ lockdown: locked }))(req),
      on('GET', '/api/v1/requests', { items: [], next_cursor: null }),
      on('GET', '/api/v1/grants', { items: [], next_cursor: null }),
      on('GET', '/api/v1/activities', { items: [] }),
      on('GET', '/api/v1/stats/overview', zeroStats),
      on('POST', '/api/v1/system/lockdown', status({ lockdown: true })),
    );
    renderInRouter(<DashboardPage />);
    expect(await screen.findByText('Pending requests', { selector: 'dt' })).toBeInTheDocument();
    expect(screen.getByText('1.2.3')).toBeInTheDocument();
    expect(await screen.findByText('No pending requests')).toBeInTheDocument();
    expect(await screen.findAllByText('No data for this period')).toHaveLength(3);
    // Requests-over-time and requests-by-state both summarize the empty range.
    expect(screen.getAllByText('No requests in the last 24 hours.', { selector: 'p' })).toHaveLength(2);

    await user.click(screen.getByRole('button', { name: 'Enable lockdown' }));
    const dialog = await screen.findByRole('dialog');
    const confirm = Array.from(dialog.querySelectorAll('button')).find(
      (b) => b.textContent === 'Enable lockdown',
    );
    expect(confirm).toBeDisabled();
    await user.type(screen.getByLabelText(/to confirm/), 'LOCKDOWN');
    expect(confirm).toBeEnabled();
    if (confirm) {
      await user.click(confirm);
    }
    await waitFor(() => {
      expect(seen.some((r) => r.method === 'POST' && r.url === '/api/v1/system/lockdown')).toBe(true);
    });
    expect(seen.find((r) => r.method === 'POST')?.headers.get('Idempotency-Key')).toMatch(/.+/);
    // The status shown afterwards is the server's response (no lift button: no lift permission).
    expect(await screen.findByText('Active')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Lift lockdown' })).not.toBeInTheDocument();
  });

  it('hides cards the operator cannot read', async () => {
    const seen = mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['requests.read'] })),
      on('GET', '/api/v1/requests', { items: [], next_cursor: null }),
      on('GET', '/api/v1/grants', { items: [], next_cursor: null }),
    );
    renderInRouter(<DashboardPage />);
    expect(await screen.findByText('No pending requests')).toBeInTheDocument();
    expect(screen.queryByText('System status')).not.toBeInTheDocument();
    expect(seen.some((r) => r.url.includes('/stats/'))).toBe(false);
  });
});

describe('<LockdownBanner>', () => {
  it('announces an active lockdown and an unacknowledged break-glass use', async () => {
    mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['dashboard.view'] })),
      on('GET', '/api/v1/system/status', status({ lockdown: true, breakglass_alert: true })),
    );
    renderInRouter(<LockdownBanner />);
    const alerts = await screen.findAllByRole('alert');
    expect(alerts.map((a) => a.textContent)).toEqual([
      expect.stringContaining('Emergency lockdown is active'),
      expect.stringContaining('break-glass recovery was used'),
    ]);
  });
});
