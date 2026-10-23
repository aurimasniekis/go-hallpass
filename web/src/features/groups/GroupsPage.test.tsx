import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse } from '../../test/fixtures';
import { renderInventory } from '../servers/testApp';

describe('groups page', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('lists groups filtered by kind on the server', async () => {
    const { calls } = renderInventory('/groups?kind=server', {
      permissions: ['inventory.read'],
      handlers: [
        [
          'GET',
          '/api/v1/groups',
          () => jsonResponse(200, { items: [{ id: 'g1', kind: 'server', name: 'db' }] }),
        ],
      ],
    });
    expect(await screen.findByText('db')).toBeInTheDocument();
    expect(calls.some((c) => c.url === '/api/v1/groups?kind=server')).toBe(true);
  });
});
