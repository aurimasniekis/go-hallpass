import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe } from '../../test/fixtures';
import { mockApi, on, renderInRouter } from '../requests/testHelpers';
import { ActivitiesPage, terminateOutcome } from './ActivitiesPage';

afterEach(() => {
  vi.restoreAllMocks();
});

const channel = {
  id: 'chn_1',
  session_id: 'ses_1',
  connection_id: 'con_1',
  agent_id: 'agt_1',
  role_id: 'rol_1',
  kind: 'session',
  pty: true,
  state: 'active',
  opened_at: '2026-01-01T00:00:00Z',
};

describe('<ActivitiesPage>', () => {
  it('lists live channels and terminates one with an Idempotency-Key', async () => {
    const user = userEvent.setup();
    const seen = mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['sessions.read', 'activities.terminate'] })),
      on('GET', '/api/v1/activities', { items: [channel] }),
      on('POST', '/api/v1/activities/chn_1/terminate', { terminated: true }, 202),
    );
    renderInRouter(<ActivitiesPage />);
    expect(await screen.findByText('Live')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'ses_1' })).toHaveAttribute('href', '/sessions/ses_1');
    await user.click(screen.getByRole('button', { name: 'Terminate channel chn_1' }));
    const dialog = await screen.findByRole('dialog');
    const confirm = Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent === 'Terminate');
    if (!confirm) {
      throw new Error('confirm missing');
    }
    await user.click(confirm);
    await waitFor(() => {
      expect(seen.some((r) => r.method === 'POST')).toBe(true);
    });
    expect(seen.find((r) => r.method === 'POST')?.headers.get('Idempotency-Key')).toMatch(/.+/);
    expect(await screen.findByText(terminateOutcome(true))).toBeInTheDocument();
  });

  it('hides terminate without activities.terminate', async () => {
    mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['sessions.read'] })),
      on('GET', '/api/v1/activities', { items: [channel] }),
    );
    renderInRouter(<ActivitiesPage />);
    expect(await screen.findByText('Live')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Terminate/ })).not.toBeInTheDocument();
  });

  it('lists recently ended channels with the reason, detail and gateway exit code', async () => {
    const failed = {
      ...channel,
      id: 'chn_2',
      kind: 'exec',
      pty: false,
      state: 'failed',
      closed_at: '2026-01-01T00:00:05Z',
      close_reason: 'failed_before_start',
      close_detail: 'destination host key changed or unknown (host verification failed)',
      gateway_exit_code: 88,
    };
    const old = {
      ...channel,
      id: 'chn_3',
      state: 'closed',
      closed_at: '2026-01-01T00:00:04Z',
      close_reason: 'exit',
      exit_status: 0,
    };
    const seen = mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['sessions.read'] })),
      (req) =>
        req.method === 'GET' && req.url.startsWith('/api/v1/activities?ended_since=')
          ? jsonResponse(200, { items: [channel, failed, old] })
          : undefined,
      on('GET', '/api/v1/activities', { items: [channel] }),
    );
    renderInRouter(<ActivitiesPage />);
    expect(await screen.findByText('Failed before it started')).toBeInTheDocument();
    expect(
      screen.getByText('destination host key changed or unknown (host verification failed)'),
    ).toBeInTheDocument();
    expect(screen.getByText('Gateway exit 88 (destination unavailable)')).toBeInTheDocument();
    expect(screen.getByText(/Gateway exit codes/)).toBeInTheDocument();
    expect(screen.getByText('Exited')).toBeInTheDocument();
    expect(seen.some((r) => r.url === '/api/v1/activities?ended_since=86400')).toBe(true);
    // The live table lists only the live channel.
    const live = screen.getByRole('region', { name: 'Live channels' });
    expect(within(live).getAllByRole('row')).toHaveLength(2);
  });

  it('describes both termination outcomes', () => {
    expect(terminateOutcome(false)).toMatch(/already ended/);
  });
});
