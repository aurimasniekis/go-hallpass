import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { makeMe } from '../../test/fixtures';
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

  it('describes both termination outcomes', () => {
    expect(terminateOutcome(false)).toMatch(/already ended/);
  });
});
