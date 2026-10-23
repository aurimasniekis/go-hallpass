import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { mockApi } from './mockApi';
import { PolicyPage } from './PolicyPage';

const rule = {
  id: 'pol_1',
  name: 'ci-deploy',
  effect: 'allow',
  level: 'requestable',
  subjects: { agents: ['agt_1'] },
  targets: { all: true },
  roles: { names: ['deploy'] },
  max_duration: 5400,
  require_reason: true,
  enabled: true,
  version: 2,
};

function setup(permissions: string[]) {
  return mockApi({
    'GET /api/v1/me': makeMe({ permissions }),
    'GET /api/v1/policy/version': { version: 7 },
    'GET /api/v1/policy/rules': { items: [rule] },
    'GET /api/v1/policy/approver-rules': { items: [] },
    'GET /api/v1/agents': { items: [{ id: 'agt_1', name: 'builder' }] },
    'GET /api/v1/servers': { items: [] },
    'GET /api/v1/groups': { items: [{ id: 'grp_1', kind: 'agent', name: 'ci' }] },
    'POST /api/v1/policy/rules': (c) => jsonResponse(201, { ...(c.body as object), id: 'pol_2', version: 1 }),
    'DELETE /api/v1/policy/rules/pol_1': () => new Response(null, { status: 204 }),
  });
}

describe('<PolicyPage>', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists rules with readable selector and duration summaries and the policy version', async () => {
    setup(['policy.read', 'inventory.read']);
    renderWithProviders(<PolicyPage />);
    expect(await screen.findByText('ci-deploy')).toBeInTheDocument();
    expect(await screen.findByText('agent: builder')).toBeInTheDocument();
    expect(screen.getByText('All servers')).toBeInTheDocument();
    expect(screen.getByText('1h 30m')).toBeInTheDocument();
    expect(await screen.findByText('7')).toBeInTheDocument();
    // Read-only operators get no write controls.
    expect(screen.queryByRole('button', { name: /New rule/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Edit rule/ })).not.toBeInTheDocument();
  });

  it('shows the permission-denied state without policy.read', async () => {
    setup(['dashboard.view']);
    renderWithProviders(<PolicyPage />);
    expect(await screen.findByText("You don't have access")).toBeInTheDocument();
  });

  it('creates a rule with only spec fields after the selectors are filled', async () => {
    const user = userEvent.setup();
    const { calls } = setup(['policy.read', 'policy.write', 'inventory.read']);
    renderWithProviders(<PolicyPage />);
    await user.click(await screen.findByRole('button', { name: /New rule/ }));
    const drawer = await screen.findByRole('dialog');
    await user.type(within(drawer).getByLabelText('Name'), 'all to all');
    await user.click(within(drawer).getByRole('button', { name: 'Create rule' }));
    // Empty selectors are refused client-side with an explanation.
    expect(await within(drawer).findByText(/Agents: the selector is empty/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    await user.click(within(drawer).getByRole('checkbox', { name: /All agents/ }));
    await user.click(within(drawer).getByRole('checkbox', { name: /All servers/ }));
    await user.click(within(drawer).getByRole('checkbox', { name: /All roles/ }));
    await user.click(within(drawer).getByRole('button', { name: 'Create rule' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST' && c.path === '/api/v1/policy/rules')).toBe(true);
    });
    const post = calls.find((c) => c.method === 'POST' && c.path === '/api/v1/policy/rules');
    expect(post?.body).toEqual({
      name: 'all to all',
      effect: 'allow',
      level: 'requestable',
      subjects: { all: true },
      targets: { all: true },
      roles: { all: true },
      require_reason: false,
      enabled: true,
    });
    expect(post?.headers.get('Idempotency-Key')).toBeTruthy();
    expect(post?.headers.get('X-CSRF-Token')).toBe('csrf-test');
  });

  it('deletes a rule only after confirmation', async () => {
    const user = userEvent.setup();
    const { calls } = setup(['policy.read', 'policy.write']);
    renderWithProviders(<PolicyPage />);
    await screen.findByText('ci-deploy');
    await user.click(screen.getByRole('button', { name: 'Delete' }));
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    await user.click(await screen.findByRole('button', { name: 'Delete rule' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'DELETE' && c.path === '/api/v1/policy/rules/pol_1')).toBe(true);
    });
  });
});
