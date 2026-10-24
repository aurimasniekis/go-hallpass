import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { mockApi } from './mockApi';
import { diffAccess, PolicyChangePreview } from './PolicyChangePreview';
import type { RuleBody } from './ruleForm';

const item = (role: string, level: string) => ({
  agent_id: 'agt_1',
  agent_name: 'builder',
  server_id: 'srv_1',
  server_alias: 'web1',
  role_id: `rol_${role}`,
  role_alias: role,
  level,
});

describe('diffAccess', () => {
  it('reports only rows whose level changes, including rows that appear or disappear', () => {
    const before = [item('deploy', 'requestable'), item('inspect', 'auto_approve'), item('gone', 'visible')];
    const after = [item('deploy', 'denied'), item('inspect', 'auto_approve'), item('new', 'visible')];
    expect(diffAccess(before, after, 'agent')).toEqual([
      {
        key: 'agt_1|srv_1|rol_deploy',
        target: 'web1',
        role: 'deploy',
        before: 'requestable',
        after: 'denied',
      },
      { key: 'agt_1|srv_1|rol_gone', target: 'web1', role: 'gone', before: 'visible', after: 'none' },
      { key: 'agt_1|srv_1|rol_new', target: 'web1', role: 'new', before: 'none', after: 'visible' },
    ]);
  });

  it('labels rows by agent when previewing a server', () => {
    const [c] = diffAccess([item('deploy', 'visible')], [], 'server');
    expect(c?.target).toBe('builder');
  });
});

const body: RuleBody = {
  name: 'block deploy',
  effect: 'deny',
  subjects: { all: true },
  targets: { all: true },
  roles: { names: ['deploy'] },
  require_reason: true,
  enabled: true,
};

describe('<PolicyChangePreview>', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('sends the unsaved rule for the chosen agent and shows the level changes', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['policy.read', 'inventory.read'] }),
      'GET /api/v1/agents': { items: [{ id: 'agt_1', name: 'builder' }] },
      'POST /api/v1/policy/preview': () =>
        jsonResponse(200, {
          before: { policy_version: 3, items: [item('deploy', 'requestable'), item('inspect', 'visible')] },
          after: { policy_version: 3, items: [item('deploy', 'denied'), item('inspect', 'visible')] },
        }),
    });
    renderWithProviders(<PolicyChangePreview build={() => body} ruleId="pol_1" />);
    await user.click(await screen.findByRole('combobox', { name: 'Preview agent' }));
    await user.click(await screen.findByTitle('builder'));
    await user.click(screen.getByRole('button', { name: 'Preview' }));

    const table = await screen.findByRole('table');
    expect(within(table).getByText('web1')).toBeInTheDocument();
    expect(within(table).getByText('Requestable')).toBeInTheDocument();
    expect(within(table).getByText('Denied')).toBeInTheDocument();
    // Unchanged rows are not listed.
    expect(within(table).queryByText('inspect')).not.toBeInTheDocument();
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.body).toEqual({ rule: { ...body, id: 'pol_1' }, agent_id: 'agt_1' });
    // A preview never saves.
    expect(calls.some((c) => c.path.startsWith('/api/v1/policy/rules'))).toBe(false);
  });

  it('says so when the change does not alter access, and sends nothing for an invalid form', async () => {
    const user = userEvent.setup();
    let valid = false;
    const { calls } = mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['policy.read', 'inventory.read'] }),
      'GET /api/v1/agents': { items: [{ id: 'agt_1', name: 'builder' }] },
      'POST /api/v1/policy/preview': () =>
        jsonResponse(200, {
          before: { policy_version: 3, items: [item('deploy', 'visible')] },
          after: { policy_version: 3, items: [item('deploy', 'visible')] },
        }),
    });
    renderWithProviders(<PolicyChangePreview build={() => (valid ? body : null)} ruleId={undefined} />);
    await user.click(await screen.findByRole('combobox', { name: 'Preview agent' }));
    await user.click(await screen.findByTitle('builder'));
    await user.click(screen.getByRole('button', { name: 'Preview' }));
    expect(calls.some((c) => c.method === 'POST')).toBe(false);

    valid = true;
    await user.click(screen.getByRole('button', { name: 'Preview' }));
    expect(await screen.findByText(/does not alter effective access/)).toBeInTheDocument();
    await waitFor(() => {
      expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ rule: body, agent_id: 'agt_1' });
    });
  });
});
