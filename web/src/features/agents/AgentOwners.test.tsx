import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { AgentDetail } from '../../api/types';
import { ReauthGate } from '../../ds/ReauthGate';
import { jsonResponse, makeMe, makeOperator, problemResponse } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { renderInventory, ts, type Handler } from '../servers/testApp';

const detail: AgentDetail = {
  id: 'ag_1',
  name: 'ci-runner',
  description: '',
  enabled: true,
  source_cidrs: [],
  groups: [],
  labels: {},
  version: 2,
  created_at: ts,
  updated_at: ts,
  keys: [],
};

const operators = [
  makeOperator({ id: 'op_1', display_name: 'Ada', email: 'ada@example.test' }),
  makeOperator({ id: 'op_2', display_name: 'Grace', email: 'grace@example.test' }),
  makeOperator({ id: 'op_3', display_name: 'Linus', email: 'linus@example.test' }),
];

/** Server-side owner list: a successful PUT replaces it, so refetches after the save see the new state. */
let stored: string[] = [];

function saveOwners(call: { body: unknown }): Response {
  stored = (call.body as { owners: string[] }).owners;
  return jsonResponse(200, { agent_id: 'ag_1', owners: stored });
}

function handlers(extra: Handler[] = []): Handler[] {
  stored = ['op_2'];
  return [
    ['GET', '/api/v1/agents/ag_1', () => jsonResponse(200, detail)],
    ['GET', '/api/v1/agents/ag_1/owners', () => jsonResponse(200, { agent_id: 'ag_1', owners: stored })],
    ['GET', '/api/v1/agents/ag_1/effective-access', () => jsonResponse(200, { items: [] })],
    ['GET', '/api/v1/operators', () => jsonResponse(200, { items: operators })],
    ...extra,
  ];
}

async function openEditor(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Edit owners' }));
  const dialog = await screen.findByRole('dialog');
  return dialog;
}

async function addOwner(user: ReturnType<typeof userEvent.setup>, dialog: HTMLElement, label: string) {
  await user.click(within(dialog).getByRole('combobox', { name: 'Owners' }));
  const option = await waitFor(() => {
    const el = document.querySelector<HTMLElement>(`.ant-select-item-option[title="${label}"]`);
    if (!el) {
      throw new Error(`option ${label} is not rendered`);
    }
    return el;
  });
  await user.click(option);
}

describe('agent owners', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists owners by display name with a link, and is read-only without policy.write', async () => {
    const { calls } = renderInventory('/agents/ag_1', {
      permissions: ['inventory.read', 'policy.read', 'operators.manage'],
      handlers: handlers(),
    });
    const owners = await screen.findByRole('list', { name: 'Agent owners' });
    const link = await within(owners).findByRole('link', { name: 'Grace' });
    expect(link).toHaveAttribute('href', '/operators/op_2');
    expect(
      screen.getByText("Owners cannot approve this agent's requests while self-approval is prohibited."),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit owners' })).not.toBeInTheDocument();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
  });

  it('is not shown without policy.read', async () => {
    const { calls } = renderInventory('/agents/ag_1', {
      permissions: ['inventory.read'],
      handlers: handlers(),
    });
    await screen.findByRole('heading', { level: 1, name: 'ci-runner' });
    expect(screen.queryByText('Owners')).not.toBeInTheDocument();
    expect(calls.some((c) => c.url.endsWith('/owners'))).toBe(false);
  });

  it('replaces the owners with policy.write and shows the server result', async () => {
    const user = userEvent.setup();
    const { calls } = renderInventory('/agents/ag_1', {
      permissions: ['inventory.read', 'policy.read', 'policy.write', 'operators.manage'],
      handlers: handlers([['PUT', '/api/v1/agents/ag_1/owners', saveOwners]]),
    });
    const dialog = await openEditor(user);
    await addOwner(user, dialog, 'Linus <linus@example.test>');
    // Nothing is sent before the operator confirms.
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
    await user.click(within(dialog).getByRole('button', { name: 'Save owners' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PUT')).toBe(true);
    });
    const put = calls.find((c) => c.method === 'PUT');
    expect(put?.body).toEqual({ owners: ['op_2', 'op_3'] });
    expect(put?.headers.get('X-CSRF-Token')).toBe('csrf-test');
    const owners = await screen.findByRole('list', { name: 'Agent owners' });
    expect(await within(owners).findByRole('link', { name: 'Linus' })).toBeInTheDocument();
  });

  it('keeps the dialog open with the server error when an operator is unknown', async () => {
    const user = userEvent.setup();
    renderInventory('/agents/ag_1', {
      permissions: ['inventory.read', 'policy.read', 'policy.write', 'operators.manage'],
      handlers: handlers([
        [
          'PUT',
          '/api/v1/agents/ag_1/owners',
          () => problemResponse(422, 'validation_failed', 'operator "op_3" not found'),
        ],
      ]),
    });
    const dialog = await openEditor(user);
    await addOwner(user, dialog, 'Linus <linus@example.test>');
    await user.click(within(dialog).getByRole('button', { name: 'Save owners' }));
    expect(await within(dialog).findByText('operator "op_3" not found')).toBeInTheDocument();
    // The list still shows the server's state, not the attempted change.
    const owners = screen.getByRole('list', { name: 'Agent owners' });
    expect(within(owners).queryByText('Linus')).not.toBeInTheDocument();
  });

  it('prompts for reauthentication and retries the save once', async () => {
    const user = userEvent.setup();
    let puts = 0;
    const { calls } = renderInventory('/agents/ag_1', {
      permissions: ['inventory.read', 'policy.read', 'policy.write', 'operators.manage'],
      handlers: handlers([
        [
          'PUT',
          '/api/v1/agents/ag_1/owners',
          (c) => {
            puts += 1;
            return puts === 1 ? problemResponse(401, 'reauth_required') : saveOwners(c);
          },
        ],
        ['POST', '/api/v1/auth/reauth', () => jsonResponse(200, makeMe({ csrf: 'rotated' }))],
      ]),
    });
    renderWithProviders(<ReauthGate />);
    const dialog = await openEditor(user);
    await addOwner(user, dialog, 'Ada <ada@example.test>');
    await user.click(within(dialog).getByRole('button', { name: 'Save owners' }));
    await user.type(await screen.findByLabelText('Password'), 'correct horse battery');
    await user.type(screen.getByLabelText('Authenticator or recovery code'), '123456');
    await user.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => {
      expect(puts).toBe(2);
    });
    const sent = calls.filter((c) => c.method === 'PUT').map((c) => c.body);
    expect(sent).toEqual([{ owners: ['op_2', 'op_1'] }, { owners: ['op_2', 'op_1'] }]);
    const owners = await screen.findByRole('list', { name: 'Agent owners' });
    expect(await within(owners).findByRole('link', { name: 'Ada' })).toBeInTheDocument();
  });
});
