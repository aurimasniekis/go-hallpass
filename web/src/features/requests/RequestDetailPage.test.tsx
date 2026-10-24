import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AccessRequest, Decision } from '../../api/types';
import { makeMe } from '../../test/fixtures';
import { RequestDetailPage } from './RequestDetailPage';
import { mockApi, on, renderInRouter } from './testHelpers';

function request(overrides: Partial<AccessRequest> = {}): AccessRequest {
  return {
    id: 'req_1',
    agent_id: 'agt_1',
    server_id: 'srv_1',
    role_id: 'rol_1',
    requested_duration: 1800,
    state: 'pending',
    policy_version: 3,
    created_at: '2026-01-01T00:00:00Z',
    expires_at: new Date(Date.now() + 600_000).toISOString(),
    has_reason: true,
    reason: 'deploy ‮fix',
    approvals_required: 1,
    approvals: [],
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('<RequestDetailPage>', () => {
  it('approves with a chosen duration and comment, sending an Idempotency-Key, and shows the server result', async () => {
    const user = userEvent.setup();
    const decision: Decision = {
      request: request({ state: 'approved' }),
      grant: {
        id: 'grt_1',
        request_id: 'req_1',
        agent_id: 'agt_1',
        server_id: 'srv_1',
        role_id: 'rol_1',
        remote_user: 'deploy',
        capabilities: ['exec'],
        starts_at: '2026-01-01T00:00:00Z',
        expires_at: '2026-01-01T01:00:00Z',
        state: 'active',
        session_id: 'ses_1',
      },
    };
    const seen = mockApi(
      on(
        'GET',
        '/api/v1/me',
        makeMe({ permissions: ['requests.read', 'requests.decide', 'requests.reason.read'] }),
      ),
      on('GET', '/api/v1/requests/req_1', request()),
      on('POST', '/api/v1/requests/req_1/approve', decision),
    );
    renderInRouter(<RequestDetailPage id="req_1" />);

    // Untrusted reason: labelled, with the bidi override revealed.
    expect(await screen.findByText('Agent reason (untrusted)')).toBeInTheDocument();
    expect(screen.getByText('<U+202E>')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Approve' }));
    await user.click(await screen.findByRole('radio', { name: '1 hour' }));
    await user.type(screen.getByLabelText(/Comment/), ' looks fine ');
    const dialog = screen.getByRole('dialog');
    const confirm = Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent === 'Approve');
    if (!confirm) {
      throw new Error('confirm button missing');
    }
    await user.click(confirm);

    expect(await screen.findByText('Approved by the server')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Open access session' })).toHaveAttribute(
      'href',
      '/sessions/ses_1',
    );
    const post = seen.find((r) => r.method === 'POST');
    expect(post?.body).toEqual({ duration: 3600, comment: 'looks fine' });
    expect(post?.headers.get('Idempotency-Key')).toMatch(/.+/);
  });

  it('shows partial approvals and records another approval without granting yet', async () => {
    const user = userEvent.setup();
    const partial = request({
      approvals_required: 3,
      approvals: [
        { operator_id: 'opr_1', channel: 'slack', duration: 3600, approved_at: '2026-01-01T00:00:00Z' },
      ],
    });
    mockApi(
      on(
        'GET',
        '/api/v1/me',
        makeMe({ permissions: ['requests.read', 'requests.decide', 'operators.read'] }),
      ),
      on('GET', '/api/v1/requests/req_1', partial),
      on('GET', '/api/v1/operators', {
        items: [{ id: 'opr_1', display_name: 'Grace Hopper', email: 'g@example.com' }],
      }),
      on('POST', '/api/v1/requests/req_1/approve', {
        request: {
          ...partial,
          approvals: [...partial.approvals, { ...partial.approvals[0], operator_id: 'opr_2' }],
        },
      }),
    );
    renderInRouter(<RequestDetailPage id="req_1" />);
    expect(await screen.findByText(/1 of 3/)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Approve' }));
    const dialog = await screen.findByRole('dialog');
    const confirm = Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent === 'Approve');
    if (!confirm) {
      throw new Error('confirm button missing');
    }
    await user.click(confirm);
    expect(await screen.findByText('Your approval is recorded (2 of 3)')).toBeInTheDocument();
    expect(screen.queryByText('Approved by the server')).not.toBeInTheDocument();
  });

  it('hides actions without decide permission and explains a hidden reason', async () => {
    mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['requests.read'] })),
      on('GET', '/api/v1/requests/req_1', request({ reason: null })),
    );
    renderInRouter(<RequestDetailPage id="req_1" />);
    expect(await screen.findByText(/hidden: viewing reasons needs/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument();
  });

  it('shows the server error when the request was already decided', async () => {
    const user = userEvent.setup();
    mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['requests.read', 'requests.decide'] })),
      on('GET', '/api/v1/requests/req_1', request()),
      (req) =>
        req.method === 'POST'
          ? new Response(
              JSON.stringify({ status: 409, code: 'conflict', detail: 'request is no longer pending' }),
              {
                status: 409,
                headers: { 'Content-Type': 'application/problem+json' },
              },
            )
          : undefined,
    );
    renderInRouter(<RequestDetailPage id="req_1" />);
    await user.click(await screen.findByRole('button', { name: 'Deny' }));
    const dialog = await screen.findByRole('dialog');
    const confirm = Array.from(dialog.querySelectorAll('button')).find((b) => b.textContent === 'Deny');
    if (!confirm) {
      throw new Error('confirm button missing');
    }
    await user.click(confirm);
    expect(await screen.findByText('request is no longer pending')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByText('Approved by the server')).not.toBeInTheDocument();
    });
  });
});
