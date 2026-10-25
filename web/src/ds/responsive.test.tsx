import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { NARROW_QUERY } from '../lib/useMediaQuery';
import { renderWithProviders } from '../test/utils';
import { DataTable, ResponsiveTable } from './DataTable';

interface Row {
  id: string;
  name: string;
}

// A phone: only max-width queries up to the narrow breakpoint match.
function phone() {
  vi.stubGlobal(
    'matchMedia',
    vi.fn((query: string) => ({
      matches: query === NARROW_QUERY || query === '(max-width: 991.98px)',
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(() => false),
    })),
  );
}

describe('tables on phones', () => {
  beforeEach(phone);
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders one labelled card per row with its actions, instead of a table', async () => {
    const onDelete = vi.fn();
    renderWithProviders(
      <DataTable<Row>
        caption="Agents"
        rowKey="id"
        rows={[
          { id: 'agt_1', name: 'ci-bot' },
          { id: 'agt_2', name: 'sre-bot' },
        ]}
        columns={[
          { key: 'name', dataIndex: 'name', title: 'Name' },
          { key: 'id', title: 'ID', render: (_, r) => <code>{r.id}</code> },
          {
            key: 'actions',
            title: <span className="hp-visually-hidden">Actions</span>,
            render: (_, r) => (
              <button
                type="button"
                onClick={() => {
                  onDelete(r.id);
                }}
              >
                Delete {r.name}
              </button>
            ),
          },
        ]}
      />,
    );
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
    const cards = within(screen.getByRole('list', { name: 'Agents' })).getAllByRole('listitem');
    expect(cards).toHaveLength(2);
    const first = cards[0];
    if (!first) {
      throw new Error('no card');
    }
    expect(within(first).getByText('Name')).toBeInTheDocument();
    expect(within(first).getByText('ci-bot')).toBeInTheDocument();
    expect(within(first).getByText('agt_1')).toBeInTheDocument();
    expect(within(first).queryByText('Actions')).not.toBeInTheDocument();
    await userEvent.click(within(first).getByRole('button', { name: 'Delete ci-bot' }));
    expect(onDelete).toHaveBeenCalledWith('agt_1');
  });

  it('shows the empty state and row details on demand', async () => {
    const { rerender } = renderWithProviders(
      <DataTable<Row>
        caption="Agents"
        rowKey="id"
        rows={[]}
        columns={[{ key: 'name', dataIndex: 'name', title: 'Name' }]}
        emptyTitle="No agents"
      />,
    );
    expect(screen.getByText('No agents')).toBeInTheDocument();
    rerender(
      <ResponsiveTable<Row>
        rowKey="id"
        dataSource={[{ id: 'agt_1', name: 'ci-bot' }]}
        columns={[{ key: 'name', dataIndex: 'name', title: 'Name' }]}
        expandable={{ expandedRowRender: (r) => <p>details of {r.name}</p> }}
      />,
    );
    expect(screen.queryByText('details of ci-bot')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Details/ }));
    expect(screen.getByText('details of ci-bot')).toBeInTheDocument();
  });
});
