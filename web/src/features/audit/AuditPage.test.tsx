import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { makeMe } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { mockApi } from '../policy/mockApi';
import { AuditPage } from './AuditPage';
import { parseAuditSearch } from './auditFilters';

const event = {
  id: 'aud_1',
  seq: 41,
  at: '2026-01-01T00:00:00Z',
  actor_type: 'agent',
  actor_id: 'agt_1',
  action: 'request.created',
  target_type: 'request',
  target_id: 'req_1',
  outcome: 'success',
  source_ip: '10.0.0.5',
  details: { reason_len: 3, note: 'abc‮def' },
};

describe('<AuditPage>', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists events with server-side filters and shows details as inert text', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['audit.read'] }),
      'GET /api/v1/audit-events': { items: [event], next_cursor: 'c2' },
    });
    const onSearchChange = vi.fn();
    renderWithProviders(<AuditPage search={{ action: 'request.created' }} onSearchChange={onSearchChange} />);
    expect(await screen.findByText('41')).toBeInTheDocument();
    expect(calls.find((c) => c.path === '/api/v1/audit-events')?.url).toBe(
      '/api/v1/audit-events?action=request.created&limit=50',
    );
    // No verify button without audit.verify.
    expect(screen.queryByRole('button', { name: /Verify hash chain/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Details of event 41' }));
    expect(await screen.findByText(/abc<U\+202E>def/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Next/ }));
    await waitFor(() => {
      expect(calls.some((c) => c.url.includes('cursor=c2'))).toBe(true);
    });
  });

  it('applies filters through the URL callback', async () => {
    const user = userEvent.setup();
    mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['audit.read'] }),
      'GET /api/v1/audit-events': { items: [], next_cursor: null },
    });
    const onSearchChange = vi.fn();
    renderWithProviders(<AuditPage search={{}} onSearchChange={onSearchChange} />);
    await user.type(await screen.findByLabelText('Target ID'), 'srv_9');
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    await waitFor(() => {
      expect(onSearchChange).toHaveBeenCalledWith({ target_id: 'srv_9' });
    });
  });

  it('verifies the hash chain on request and reports failures plainly', async () => {
    const user = userEvent.setup();
    mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['audit.read', 'audit.verify'] }),
      'GET /api/v1/audit-events': { items: [], next_cursor: null },
      'GET /api/v1/audit-events/verify': { ok: false, events: 12, problem: 'hash mismatch at seq 7' },
    });
    renderWithProviders(<AuditPage search={{}} onSearchChange={vi.fn()} />);
    await user.click(await screen.findByRole('button', { name: /Verify hash chain/ }));
    expect(await screen.findByText('Hash chain verification FAILED')).toBeInTheDocument();
    expect(screen.getByText('hash mismatch at seq 7')).toBeInTheDocument();
  });
});

describe('parseAuditSearch', () => {
  it('keeps only known, safe, trimmed values', () => {
    expect(
      parseAuditSearch({ action: ' request.created ', actor_id: 'op_1', evil: 'x', target_id: 'a b' }),
    ).toEqual({
      action: 'request.created',
      actor_id: 'op_1',
    });
    expect(parseAuditSearch({ action: 5 })).toEqual({});
  });
});
