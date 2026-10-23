import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { makeMe } from '../../test/fixtures';
import { RequestsPage } from './RequestsPage';
import { mockApi, on, renderInRouter } from './testHelpers';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('<RequestsPage>', () => {
  it('sends URL filters to the server and pages with next_cursor', async () => {
    const seen = mockApi(
      on('GET', '/api/v1/me', makeMe({ permissions: ['requests.read'] })),
      on('GET', '/api/v1/requests', {
        items: [
          {
            id: 'req_1',
            agent_id: 'agt_1',
            server_id: 'srv_1',
            role_id: 'rol_1',
            requested_duration: 5400,
            state: 'denied',
            policy_version: 1,
            created_at: '2026-01-01T00:00:00Z',
            expires_at: '2026-01-01T00:10:00Z',
            has_reason: false,
          },
        ],
        next_cursor: 'cur2',
      }),
    );
    renderInRouter(<RequestsPage search={{ state: 'denied', agent_id: 'agt_1' }} onSearchChange={vi.fn()} />);
    expect(await screen.findByText('1h 30m')).toBeInTheDocument();
    expect(
      within(screen.getByRole('region', { name: 'Access requests' })).getByText('Denied'),
    ).toBeInTheDocument();
    const list = seen.find((r) => r.url.startsWith('/api/v1/requests'));
    expect(list?.url).toBe('/api/v1/requests?state=denied&agent_id=agt_1&limit=50');
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Next/ })).toBeEnabled();
    });
    screen.getByRole('button', { name: /Next/ }).click();
    await waitFor(() => {
      expect(seen.some((r) => r.url.includes('cursor=cur2'))).toBe(true);
    });
  });

  it('renders permission denied without requests.read', async () => {
    mockApi(on('GET', '/api/v1/me', makeMe({ permissions: ['dashboard.view'] })));
    renderInRouter(<RequestsPage search={{}} onSearchChange={vi.fn()} />);
    expect(await screen.findByText("You don't have access")).toBeInTheDocument();
  });
});
