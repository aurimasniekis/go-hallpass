import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Card, Select, Space } from 'antd';

import { agentsQueryOptions, requestListQueryOptions, serversQueryOptions } from '../../api/queries';
import type { AccessRequest } from '../../api/types';
import { Countdown } from '../../ds/Countdown';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { SavedFilters } from '../../ds/SavedFilters';
import { LoadingState, PermissionDenied } from '../../ds/states';
import { formatDateTime, formatDuration, formatRelative } from '../../lib/format';
import { useCursorPager } from '../../lib/useCursorPager';
import { useNow } from '../../lib/useNow';
import { usePermissions } from '../../lib/usePermissions';
import { revealControls } from '../../ds/untrusted';
import { AgentName, RoleName, ServerName } from '../../shared/names';
import { StateBadge } from '../../shared/StateBadge';
import { stateDisplay } from '../../shared/states';
import { useSseState } from '../../stores/sse';
import { REQUEST_STATES, searchFromSaved, searchToFilters, type RequestSearch } from './search';

const PAGE_SIZE = 50;

export interface RequestsPageProps {
  search: RequestSearch;
  onSearchChange: (next: RequestSearch) => void;
}

/** Access requests (HP-UI-003/008): server-side filters in the URL, cursor pages, saved filters. */
export function RequestsPage({ search, onSearchChange }: RequestsPageProps) {
  const { can, loading } = usePermissions();
  const canInventory = can('inventory.read');
  const agents = useQuery({ ...agentsQueryOptions(), enabled: canInventory });
  const servers = useQuery({ ...serversQueryOptions(), enabled: canInventory });
  const pager = useCursorPager(JSON.stringify(search));
  const list = useQuery({
    ...requestListQueryOptions({ ...search, limit: PAGE_SIZE, cursor: pager.cursor }),
    enabled: can('requests.read'),
  });
  const sse = useSseState();
  const now = useNow(15_000);

  if (loading) {
    return <LoadingState />;
  }
  if (!can('requests.read')) {
    return (
      <>
        <PageHeader title="Requests" />
        <PermissionDenied />
      </>
    );
  }

  const set = (patch: Partial<RequestSearch>) => {
    const merged: RequestSearch = { ...search, ...patch };
    onSearchChange(Object.fromEntries(Object.entries(merged).filter(([, v]) => v !== undefined)));
  };

  return (
    <>
      <PageHeader title="Requests" description="Access requests from agents awaiting or past decision." />
      <Card size="small">
        <Space wrap style={{ marginBottom: 12 }}>
          <Select
            aria-label="Filter by state"
            placeholder="Any state"
            allowClear
            style={{ minWidth: 150 }}
            value={search.state}
            onChange={(v: RequestSearch['state']) => {
              set({ state: v });
            }}
            options={REQUEST_STATES.map((s) => ({ value: s, label: stateDisplay('request', s).label }))}
          />
          {canInventory ? (
            <Select
              aria-label="Filter by agent"
              placeholder="Any agent"
              allowClear
              showSearch={{ optionFilterProp: 'label' }}
              style={{ minWidth: 180 }}
              value={search.agent_id}
              loading={agents.isPending}
              onChange={(v: string | undefined) => {
                set({ agent_id: v });
              }}
              options={agents.data?.items.map((a) => ({ value: a.id, label: a.name }))}
            />
          ) : null}
          {canInventory ? (
            <Select
              aria-label="Filter by server"
              placeholder="Any server"
              allowClear
              showSearch={{ optionFilterProp: 'label' }}
              style={{ minWidth: 180 }}
              value={search.server_id}
              loading={servers.isPending}
              onChange={(v: string | undefined) => {
                set({ server_id: v });
              }}
              options={servers.data?.items.map((s) => ({ value: s.id, label: s.alias }))}
            />
          ) : null}
          <SavedFilters
            table="requests"
            current={searchToFilters(search)}
            onApply={(filters) => {
              onSearchChange(searchFromSaved(filters));
            }}
          />
        </Space>
        <DataTable<AccessRequest>
          caption="Access requests"
          rowKey="id"
          rows={list.data?.items}
          loading={list.isPending}
          fetching={list.isFetching}
          error={list.error}
          onRetry={() => void list.refetch()}
          stale={sse.status === 'stale' || sse.status === 'disconnected'}
          emptyTitle="No requests match these filters"
          pagination={{
            pageSize: PAGE_SIZE,
            hasPreviousPage: pager.hasPrevious,
            hasNextPage: Boolean(list.data?.next_cursor),
            onPreviousPage: pager.previous,
            onNextPage: () => {
              pager.next(list.data?.next_cursor);
            },
          }}
          columns={[
            {
              key: 'created',
              title: 'Created',
              render: (_v, r) => (
                <Link to="/requests/$id" params={{ id: r.id }} title={formatDateTime(r.created_at)}>
                  {formatRelative(r.created_at, now)}
                </Link>
              ),
            },
            {
              key: 'agent',
              title: 'Agent',
              render: (_v, r) => (
                <>
                  <AgentName id={r.agent_id} />
                  {r.agent_session ? (
                    <span
                      className="hp-legend"
                      style={{ display: 'block' }}
                      title={revealControls(r.agent_session)}
                    >
                      session {revealControls(r.agent_session).slice(0, 8)}
                    </span>
                  ) : null}
                </>
              ),
            },
            { key: 'server', title: 'Server', render: (_v, r) => <ServerName id={r.server_id} /> },
            { key: 'role', title: 'Role', render: (_v, r) => <RoleName id={r.role_id} /> },
            {
              key: 'duration',
              title: 'Requested',
              render: (_v, r) => formatDuration(r.requested_duration),
            },
            {
              key: 'state',
              title: 'State',
              render: (_v, r) => <StateBadge kind="request" state={r.state} />,
            },
            {
              key: 'expires',
              title: 'Expires',
              render: (_v, r) => (r.state === 'pending' ? <Countdown deadline={r.expires_at} /> : '—'),
            },
            { key: 'reason', title: 'Reason', render: (_v, r) => (r.has_reason ? 'Provided' : 'None') },
          ]}
        />
      </Card>
    </>
  );
}
