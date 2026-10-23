import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ApiError } from '../api/errors';
import type { SseState } from '../stores/sse';
import { renderWithProviders } from '../test/utils';
import { ChartCard } from './ChartCard';
import { ConnectionBanner } from './ConnectionBanner';
import { DataTable, fromSortParam, toSortParam } from './DataTable';
import { hasPermissions } from './permissions';
import { PermissionGate } from './PermissionGate';
import { StatusBadge } from './StatusBadge';

vi.mock('./EChart', () => ({
  EChart: ({ ariaLabel, describedBy }: { ariaLabel: string; describedBy?: string }) => (
    <div role="img" aria-label={ariaLabel} aria-describedby={describedBy} />
  ),
}));

describe('hasPermissions / <PermissionGate>', () => {
  it('supports all/any modes and denies when unknown', () => {
    expect(hasPermissions(['a', 'b'], ['a', 'b'])).toBe(true);
    expect(hasPermissions(['a'], ['a', 'b'])).toBe(false);
    expect(hasPermissions(['a'], ['a', 'b'], 'any')).toBe(true);
    expect(hasPermissions(undefined, 'a')).toBe(false);
  });

  it('renders children or the permission-denied state', () => {
    const { rerender } = renderWithProviders(
      <PermissionGate permission="grants.revoke" permissions={['grants.revoke']}>
        <button type="button">Revoke</button>
      </PermissionGate>,
    );
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeInTheDocument();
    rerender(
      <PermissionGate permission="grants.revoke" permissions={[]}>
        <button type="button">Revoke</button>
      </PermissionGate>,
    );
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument();
    expect(screen.getByText("You don't have access")).toBeInTheDocument();
  });
});

describe('<ConnectionBanner>', () => {
  const base: SseState = { status: 'connected', lastEventAt: null, disconnectedAt: null, attempt: 0 };

  it('is silent while connected and explains stale/disconnected states', async () => {
    const onReconnect = vi.fn();
    const { rerender, container } = renderWithProviders(
      <ConnectionBanner state={base} onReconnect={onReconnect} />,
    );
    expect(container.textContent).toBe('');
    rerender(<ConnectionBanner state={{ ...base, status: 'reconnecting' }} onReconnect={onReconnect} />);
    expect(screen.getByText(/Reconnecting/)).toBeInTheDocument();
    rerender(
      <ConnectionBanner state={{ ...base, status: 'stale', disconnectedAt: 0 }} onReconnect={onReconnect} />,
    );
    expect(screen.getByText(/may be out of date/)).toBeInTheDocument();
    rerender(<ConnectionBanner state={{ ...base, status: 'disconnected' }} onReconnect={onReconnect} />);
    await userEvent.click(screen.getByRole('button', { name: 'Reconnect' }));
    expect(onReconnect).toHaveBeenCalledTimes(1);
  });
});

describe('<DataTable>', () => {
  interface Row {
    id: string;
    name: string;
  }
  const columns = [
    { key: 'name', dataIndex: 'name', title: 'Name', sorter: true },
    { key: 'id', dataIndex: 'id', title: 'ID' },
  ];

  it('converts sort state to and from the API syntax', () => {
    expect(toSortParam({ field: 'created_at', order: 'descend' })).toBe('-created_at');
    expect(toSortParam({ field: 'name', order: 'ascend' })).toBe('name');
    expect(toSortParam(null)).toBeUndefined();
    expect(fromSortParam('-created_at')).toEqual({ field: 'created_at', order: 'descend' });
  });

  it('renders the empty state', () => {
    renderWithProviders(
      <DataTable<Row> caption="Agents" columns={columns} rows={[]} rowKey="id" emptyTitle="No agents" />,
    );
    expect(screen.getByText('No agents')).toBeInTheDocument();
  });

  it('renders the error state with retry, and permission denied for 403', async () => {
    const onRetry = vi.fn();
    const { rerender } = renderWithProviders(
      <DataTable<Row>
        caption="Agents"
        columns={columns}
        rows={undefined}
        rowKey="id"
        error={new ApiError({ status: 500, code: 'internal', detail: 'Boom' })}
        onRetry={onRetry}
      />,
    );
    expect(screen.getByText('Boom')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalled();
    rerender(
      <DataTable<Row>
        caption="Agents"
        columns={columns}
        rows={undefined}
        rowKey="id"
        error={new ApiError({ status: 403, code: 'forbidden', detail: 'Needs inventory.read' })}
      />,
    );
    expect(screen.getByText("You don't have access")).toBeInTheDocument();
  });

  it('keeps rows visible with stale and refresh-failure notices', () => {
    renderWithProviders(
      <DataTable<Row>
        caption="Agents"
        columns={columns}
        rows={[{ id: 'a1', name: 'builder' }]}
        rowKey="id"
        stale
        error={new Error('x')}
      />,
    );
    expect(screen.getByText('builder')).toBeInTheDocument();
    expect(screen.getByText(/may be out of date/)).toBeInTheDocument();
    expect(screen.getByText(/showing the last loaded data/)).toBeInTheDocument();
  });

  it('delegates sorting to the server and pages by cursor', async () => {
    const user = userEvent.setup();
    const onSortChange = vi.fn();
    const onNextPage = vi.fn();
    renderWithProviders(
      <DataTable<Row>
        caption="Agents"
        columns={columns}
        rows={[
          { id: 'b', name: 'zeta' },
          { id: 'a', name: 'alpha' },
        ]}
        rowKey="id"
        sort={null}
        onSortChange={onSortChange}
        pagination={{
          pageSize: 50,
          hasPreviousPage: false,
          hasNextPage: true,
          onPreviousPage: () => undefined,
          onNextPage,
        }}
      />,
    );
    const header = screen.getAllByText('Name').at(0);
    if (!header) {
      throw new Error('missing Name header');
    }
    await user.click(header);
    expect(onSortChange).toHaveBeenCalledWith({ field: 'name', order: 'ascend' });
    // Rows stay in server order: no client-side sorting.
    const cells = screen.getAllByRole('cell').map((c) => c.textContent);
    expect(cells.indexOf('zeta')).toBeLessThan(cells.indexOf('alpha'));
    expect(screen.getByRole('button', { name: /Previous/ })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: /Next/ }));
    expect(onNextPage).toHaveBeenCalled();
  });
});

describe('<ChartCard>', () => {
  it('links the summary and toggles a table alternative', async () => {
    const user = userEvent.setup();
    renderWithProviders(
      <ChartCard
        title="Requests"
        summary="12 requests in the last 24 hours."
        option={{}}
        table={{
          columns: [
            { key: 't', title: 'Time' },
            { key: 'v', title: 'Count' },
          ],
          rows: [{ t: '10:00', v: 12 }],
        }}
      />,
    );
    const img = await screen.findByRole('img', { name: 'Requests' });
    const summaryId = img.getAttribute('aria-describedby');
    expect(summaryId).toBeTruthy();
    expect(document.getElementById(summaryId ?? '')).toHaveTextContent('12 requests');
    await user.click(screen.getByRole('button', { name: 'View as table' }));
    expect(screen.getByText('10:00')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View as chart' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('shows empty and error states instead of a chart', () => {
    const { rerender } = renderWithProviders(
      <ChartCard title="Requests" summary="s" option={{}} table={{ columns: [], rows: [] }} empty />,
    );
    expect(screen.getByText('No data for this period')).toBeInTheDocument();
    rerender(
      <ChartCard
        title="Requests"
        summary="s"
        option={{}}
        table={{ columns: [], rows: [] }}
        error={new Error('stats down')}
      />,
    );
    expect(screen.getByText('stats down')).toBeInTheDocument();
  });
});

describe('<StatusBadge>', () => {
  it('always carries a text label', () => {
    renderWithProviders(<StatusBadge tone="error">Revoked</StatusBadge>);
    expect(screen.getByText('Revoked')).toBeInTheDocument();
  });
});
