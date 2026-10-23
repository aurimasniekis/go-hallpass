import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe } from '../../test/fixtures';
import { renderWithProviders } from '../../test/utils';
import { mockApi } from '../policy/mockApi';
import { IntegrationsPage } from './IntegrationsPage';

const slack = {
  id: 'int_1',
  provider: 'slack',
  name: 'Ops Slack',
  config: { team_id: 'T012' },
  secrets_set: ['bot_token', 'signing_secret'],
  enabled: true,
  version: 3,
  webhook_path: '/hooks/slack/int_1',
};

function setup() {
  return mockApi({
    'GET /api/v1/me': makeMe({ permissions: ['integrations.manage'] }),
    'GET /api/v1/integrations': { items: [slack] },
    'GET /api/v1/notification-routes': {
      items: [
        {
          id: 'nr_1',
          integration_id: 'int_1',
          provider: 'slack',
          destination: 'C0123',
          targets: { server_groups: ['prod'] },
          enabled: true,
        },
      ],
    },
    'GET /api/v1/notification-deliveries': {
      items: [
        {
          id: 'd1',
          provider: 'slack',
          destination: 'C0123',
          kind: 'request.pending',
          state: 'dead',
          attempts: 8,
          max_attempts: 8,
          last_error: 'channel_not_found‮',
          created_at: '2026-01-01T00:00:00Z',
        },
      ],
    },
    'POST /api/v1/integrations': (c) => jsonResponse(201, { ...slack, id: 'int_2', ...(c.body as object) }),
    'PATCH /api/v1/integrations/int_1': (c) =>
      jsonResponse(200, { ...slack, ...(c.body as object), version: 4 }),
  });
}

describe('<IntegrationsPage>', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows integrations with their webhook URL and stored-secret names, never secret values', async () => {
    setup();
    renderWithProviders(<IntegrationsPage />);
    expect(await screen.findByText('Ops Slack')).toBeInTheDocument();
    expect(screen.getByDisplayValue(`${window.location.origin}/hooks/slack/int_1`)).toBeInTheDocument();
    expect(screen.getByText(/bot_token, signing_secret/)).toBeInTheDocument();
  });

  it('edits without resending secrets unless typed, using If-Match', async () => {
    const user = userEvent.setup();
    const { calls } = setup();
    renderWithProviders(<IntegrationsPage />);
    await user.click(await screen.findByRole('button', { name: /Edit/ }));
    const drawer = await screen.findByRole('dialog');
    expect(within(drawer).getByLabelText('Bot token (stored)')).toHaveValue('');
    await user.type(within(drawer).getByLabelText('Signing secret (stored)'), 'new-signing-secret');
    await user.click(within(drawer).getByRole('button', { name: 'Save integration' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PATCH')).toBe(true);
    });
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.headers.get('If-Match')).toBe('"3"');
    expect(patch?.body).toEqual({
      name: 'Ops Slack',
      config: { team_id: 'T012' },
      enabled: true,
      secrets: { signing_secret: 'new-signing-secret' },
    });
  });

  it('shows routes and highlights dead-letter deliveries with revealed control characters', async () => {
    const user = userEvent.setup();
    setup();
    renderWithProviders(<IntegrationsPage />);
    await user.click(await screen.findByRole('tab', { name: 'Routes' }));
    expect(await screen.findByText('groups: prod')).toBeInTheDocument();
    await user.click(screen.getByRole('tab', { name: 'Deliveries' }));
    expect(await screen.findByText(/failed permanently \(dead letter\)/)).toBeInTheDocument();
    expect(screen.getByText('channel_not_found<U+202E>')).toBeInTheDocument();
    expect(screen.getByText('8 / 8')).toBeInTheDocument();
  });

  it('denies operators without integrations.manage', async () => {
    mockApi({ 'GET /api/v1/me': makeMe({ permissions: ['dashboard.view'] }) });
    renderWithProviders(<IntegrationsPage />);
    expect(await screen.findByText("You don't have access")).toBeInTheDocument();
  });
});
