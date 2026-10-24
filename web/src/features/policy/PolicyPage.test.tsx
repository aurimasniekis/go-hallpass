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

function setup(permissions: string[], prohibit = true) {
  let prohibitSelfApproval = prohibit;
  return mockApi({
    'GET /api/v1/me': makeMe({ permissions }),
    'GET /api/v1/policy/version': { version: 7 },
    'GET /api/v1/policy/self-approval': () =>
      jsonResponse(200, { prohibit_self_approval: prohibitSelfApproval }),
    'PUT /api/v1/policy/self-approval': (c) => {
      prohibitSelfApproval = (c.body as { prohibit_self_approval: boolean }).prohibit_self_approval;
      return jsonResponse(200, { prohibit_self_approval: prohibitSelfApproval });
    },
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
      // New rules require a reason by default, matching the server default.
      require_reason: true,
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

  describe('self-approval', () => {
    it('shows the current value without a switch for read-only operators', async () => {
      setup(['policy.read']);
      renderWithProviders(<PolicyPage />);
      expect(await screen.findByText('Prohibited')).toBeInTheDocument();
      expect(screen.queryByRole('switch')).not.toBeInTheDocument();
    });

    it('turning the prohibition off warns about owners and needs the typed phrase', async () => {
      const user = userEvent.setup();
      const { calls } = setup(['policy.read', 'policy.write']);
      renderWithProviders(<PolicyPage />);
      const toggle = await screen.findByRole('switch', { name: 'Prohibit self-approval' });
      expect(toggle).toBeChecked();
      await user.click(toggle);
      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).getByText('Owners will be able to approve their own agents')).toBeInTheDocument();
      // The switch does not move before the server confirms.
      expect(toggle).toBeChecked();
      const confirm = within(dialog).getByRole('button', { name: 'Allow self-approval' });
      expect(confirm).toBeDisabled();
      await user.type(within(dialog).getByLabelText(/to confirm/), 'ALLOW SELF-APPROVAL');
      await user.click(confirm);
      await waitFor(() => {
        expect(screen.getByRole('switch', { name: 'Prohibit self-approval' })).not.toBeChecked();
      });
      expect(screen.getByText('Allowed')).toBeInTheDocument();
      const put = calls.find((c) => c.method === 'PUT' && c.path === '/api/v1/policy/self-approval');
      expect(put?.body).toEqual({ prohibit_self_approval: false });
      expect(put?.headers.get('X-CSRF-Token')).toBe('csrf-test');
    });

    it('turning the prohibition on asks for confirmation without the owner warning', async () => {
      const user = userEvent.setup();
      const { calls } = setup(['policy.read', 'policy.write'], false);
      renderWithProviders(<PolicyPage />);
      expect(await screen.findByText('Allowed')).toBeInTheDocument();
      await user.click(screen.getByRole('switch', { name: 'Prohibit self-approval' }));
      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).queryByText('Owners will be able to approve their own agents')).toBeNull();
      await user.type(within(dialog).getByLabelText(/to confirm/), 'PROHIBIT SELF-APPROVAL');
      await user.click(within(dialog).getByRole('button', { name: 'Prohibit self-approval' }));
      expect(await screen.findByText('Prohibited')).toBeInTheDocument();
      expect(calls.find((c) => c.method === 'PUT')?.body).toEqual({ prohibit_self_approval: true });
    });

    it('cancelling sends nothing and leaves the value unchanged', async () => {
      const user = userEvent.setup();
      const { calls } = setup(['policy.read', 'policy.write']);
      renderWithProviders(<PolicyPage />);
      await user.click(await screen.findByRole('switch', { name: 'Prohibit self-approval' }));
      const dialog = await screen.findByRole('dialog');
      await user.click(within(dialog).getByRole('button', { name: 'Cancel' }));
      expect(screen.getByRole('switch', { name: 'Prohibit self-approval' })).toBeChecked();
      expect(calls.some((c) => c.method === 'PUT')).toBe(false);
    });
  });
});
