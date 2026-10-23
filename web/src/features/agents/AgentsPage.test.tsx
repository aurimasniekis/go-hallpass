import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { Agent, AgentDetail } from '../../api/types';
import { jsonResponse } from '../../test/fixtures';
import { renderInventory, ts } from '../servers/testApp';

const agent: Agent = {
  id: 'ag_1',
  name: 'ci-runner',
  description: 'Builds things',
  enabled: true,
  source_cidrs: [],
  groups: ['ci'],
  labels: { env: 'prod' },
  version: 2,
  created_at: ts,
  updated_at: ts,
};

const detail: AgentDetail = {
  ...agent,
  keys: [
    {
      id: 'k1',
      agent_id: 'ag_1',
      fingerprint: 'SHA256:abc',
      algorithm: 'ssh-ed25519',
      public_key: 'ssh-ed25519 AAAA',
      comment: 'evil‮comment',
      state: 'active',
      created_at: ts,
    },
  ],
};

describe('agents pages', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists agents and creates one with an idempotency key, then opens it', async () => {
    const user = userEvent.setup();
    const { calls, router } = renderInventory('/agents', {
      permissions: ['inventory.read', 'inventory.write'],
      handlers: [
        ['GET', '/api/v1/agents', () => jsonResponse(200, { items: [agent] })],
        ['POST', '/api/v1/agents', () => jsonResponse(201, { ...agent, id: 'ag_2', name: 'new-agent' })],
        ['GET', '/api/v1/agents/ag_2', () => jsonResponse(200, { ...detail, id: 'ag_2', name: 'new-agent' })],
      ],
    });
    expect(await screen.findByRole('link', { name: 'ci-runner' })).toHaveAttribute('href', '/agents/ag_1');
    await user.click(screen.getByRole('button', { name: /New agent/ }));
    const dialog = await screen.findByRole('dialog');
    await user.type(within(dialog).getByLabelText('Name'), 'new-agent');
    await user.type(within(dialog).getByLabelText(/^Public keys/), 'ssh-ed25519 AAAA one');
    await user.click(within(dialog).getByRole('button', { name: 'Create agent' }));
    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/agents/ag_2');
    });
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.body).toEqual({
      name: 'new-agent',
      description: '',
      enabled: true,
      source_cidrs: [],
      groups: [],
      labels: {},
      public_keys: ['ssh-ed25519 AAAA one'],
    });
    expect(post?.headers.get('Idempotency-Key')).toBeTruthy();
  });

  it('hides write actions without inventory.write', async () => {
    renderInventory('/agents', {
      permissions: ['inventory.read'],
      handlers: [['GET', '/api/v1/agents', () => jsonResponse(200, { items: [agent] })]],
    });
    await screen.findByRole('link', { name: 'ci-runner' });
    expect(screen.queryByRole('button', { name: /New agent/ })).not.toBeInTheDocument();
  });

  it('shows permission denied without inventory.read', async () => {
    renderInventory('/agents', { permissions: ['dashboard.view'], handlers: [] });
    expect(await screen.findByText("You don't have access")).toBeInTheDocument();
  });

  it('detail: renders key comments as untrusted text and patches with If-Match', async () => {
    const user = userEvent.setup();
    const { calls } = renderInventory('/agents/ag_1', {
      permissions: ['inventory.read', 'inventory.write'],
      handlers: [
        ['GET', '/api/v1/agents/ag_1', () => jsonResponse(200, detail)],
        ['PATCH', '/api/v1/agents/ag_1', () => jsonResponse(200, { ...agent, description: 'x', version: 3 })],
      ],
    });
    expect(await screen.findByRole('heading', { level: 1, name: 'ci-runner' })).toBeInTheDocument();
    // The bidi override in the key comment is revealed, not applied.
    expect(screen.getByText('<U+202E>')).toBeInTheDocument();
    // Effective access is not shown without policy.read.
    expect(screen.queryByText('Effective access')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog');
    const desc = within(dialog).getByLabelText(/^Description/);
    await user.clear(desc);
    await user.type(desc, 'x');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PATCH')).toBe(true);
    });
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.headers.get('If-Match')).toBe('"2"');
    expect(patch?.body).toEqual({
      version: 2,
      name: 'ci-runner',
      description: 'x',
      source_cidrs: [],
      groups: ['ci'],
      labels: { env: 'prod' },
    });
  });

  it('detail: shows a reload hint when the agent changed concurrently', async () => {
    const user = userEvent.setup();
    renderInventory('/agents/ag_1', {
      permissions: ['inventory.read', 'inventory.write'],
      handlers: [
        ['GET', '/api/v1/agents/ag_1', () => jsonResponse(200, detail)],
        [
          'PATCH',
          '/api/v1/agents/ag_1',
          () =>
            jsonResponse(
              409,
              {
                type: 'about:blank',
                title: 'conflict',
                status: 409,
                code: 'conflict',
                detail: 'version mismatch',
              },
              'application/problem+json',
            ),
        ],
      ],
    });
    await user.click(await screen.findByRole('button', { name: 'Edit' }));
    const dialog = await screen.findByRole('dialog');
    await user.click(within(dialog).getByRole('button', { name: 'Save' }));
    expect(await within(dialog).findByText('version mismatch')).toBeInTheDocument();
    expect(within(dialog).getByText(/changed since you opened it/)).toBeInTheDocument();
  });
});
