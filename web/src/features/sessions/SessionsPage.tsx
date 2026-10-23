import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Card, Select, Space, Tabs } from 'antd';
import type { TableColumnsType } from 'antd';

import {
  agentsQueryOptions,
  grantListQueryOptions,
  serversQueryOptions,
  sessionListQueryOptions,
  type GrantFilters,
  type SessionFilters,
} from '../../api/queries';
import type { AccessSession, Grant } from '../../api/types';
import { Countdown } from '../../ds/Countdown';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { SavedFilters } from '../../ds/SavedFilters';
import { PermissionDenied } from '../../ds/states';
import { formatDateTime, shortId } from '../../lib/format';
import { useCursorPager } from '../../lib/useCursorPager';
import { usePermissions } from '../../lib/usePermissions';
import { AgentName, RoleName, ServerName } from '../../shared/names';
import { StateBadge } from '../../shared/StateBadge';
import { useSseStatus } from '../../stores/sse';
import { RevokeGrantButton } from './GrantActions';
import { orDash } from './text';
import { GRANT_STATES, SESSION_STATES, type SessionsSearch, type SessionsTab } from './search';

const PAGE_SIZE = 50;

export interface SessionsPageProps {
  search: SessionsSearch;
  onSearchChange: (next: SessionsSearch) => void;
}

function useStale(): boolean {
  const status = useSseStatus();
  return status === 'stale' || status === 'disconnected';
}

function Filters({
  search,
  states,
  onSearchChange,
  table,
}: {
  search: SessionsSearch;
  states: readonly string[];
  onSearchChange: (next: SessionsSearch) => void;
  table: string;
}) {
  const { can } = usePermissions();
  const agents = useQuery({ ...agentsQueryOptions(), enabled: can('inventory.read') });
  const servers = useQuery({ ...serversQueryOptions(), enabled: can('inventory.read') });
  const set = (patch: Partial<SessionsSearch>) => {
    const merged: SessionsSearch = { ...search, ...patch };
    onSearchChange({
      ...(merged.tab ? { tab: merged.tab } : {}),
      ...(merged.state ? { state: merged.state } : {}),
      ...(merged.agent_id ? { agent_id: merged.agent_id } : {}),
      ...(merged.server_id ? { server_id: merged.server_id } : {}),
    });
  };
  const current = {
    state: search.state ?? '',
    agent_id: search.agent_id ?? '',
    server_id: search.server_id ?? '',
  };
  return (
    <Space wrap style={{ marginBottom: 12 }}>
      <Select<string>
        aria-label="Filter by state"
        placeholder="Any state"
        allowClear
        value={search.state}
        style={{ width: 150 }}
        options={states.map((s) => ({ value: s, label: s }))}
        onChange={(v) => {
          set({ state: v });
        }}
      />
      <Select<string>
        aria-label="Filter by agent"
        placeholder="Any agent"
        allowClear
        showSearch={{ optionFilterProp: 'label' }}
        value={search.agent_id}
        style={{ width: 200 }}
        options={(agents.data?.items ?? []).map((a) => ({ value: a.id, label: a.name }))}
        onChange={(v) => {
          set({ agent_id: v });
        }}
      />
      <Select<string>
        aria-label="Filter by server"
        placeholder="Any server"
        allowClear
        showSearch={{ optionFilterProp: 'label' }}
        value={search.server_id}
        style={{ width: 200 }}
        options={(servers.data?.items ?? []).map((s) => ({ value: s.id, label: s.alias }))}
        onChange={(v) => {
          set({ server_id: v });
        }}
      />
      <SavedFilters
        table={table}
        current={current}
        onApply={(f) => {
          onSearchChange({
            ...(search.tab ? { tab: search.tab } : {}),
            ...(f.state ? { state: f.state } : {}),
            ...(f.agent_id ? { agent_id: f.agent_id } : {}),
            ...(f.server_id ? { server_id: f.server_id } : {}),
          });
        }}
      />
    </Space>
  );
}

function SessionsTable({ search, onSearchChange }: SessionsPageProps) {
  const filters = {
    ...(search.state ? { state: search.state as NonNullable<SessionFilters['state']> } : {}),
    ...(search.agent_id ? { agent_id: search.agent_id } : {}),
    ...(search.server_id ? { server_id: search.server_id } : {}),
  };
  const pager = useCursorPager(JSON.stringify(filters));
  const q = useQuery(
    sessionListQueryOptions({
      ...filters,
      limit: PAGE_SIZE,
      ...(pager.cursor ? { cursor: pager.cursor } : {}),
    }),
  );
  const stale = useStale();
  const columns: TableColumnsType<AccessSession> = [
    {
      key: 'id',
      title: 'Session',
      render: (_, s) => (
        <Link to="/sessions/$id" params={{ id: s.id }}>
          <code className="hp-mono" title={s.id}>
            {shortId(s.id)}
          </code>
        </Link>
      ),
    },
    { key: 'opened', title: 'Opened', render: (_, s) => formatDateTime(s.opened_at) },
    { key: 'closed', title: 'Closed', render: (_, s) => (s.closed_at ? formatDateTime(s.closed_at) : '—') },
    { key: 'agent', title: 'Agent', render: (_, s) => <AgentName id={s.agent_id} /> },
    { key: 'server', title: 'Server', render: (_, s) => <ServerName id={s.server_id} /> },
    { key: 'role', title: 'Role', render: (_, s) => <RoleName id={s.role_id} /> },
    { key: 'user', title: 'Remote user', render: (_, s) => <code className="hp-mono">{s.remote_user}</code> },
    { key: 'state', title: 'State', render: (_, s) => <StateBadge kind="session" state={s.state} /> },
    { key: 'grant', title: 'Grant', render: (_, s) => <StateBadge kind="grant" state={s.grant_state} /> },
    {
      key: 'remaining',
      title: 'Grant ends',
      render: (_, s) =>
        s.grant_state === 'active' ? (
          <Countdown deadline={s.grant_expires_at} />
        ) : (
          formatDateTime(s.grant_expires_at)
        ),
    },
  ];
  return (
    <>
      <Filters search={search} states={SESSION_STATES} onSearchChange={onSearchChange} table="sessions" />
      <DataTable<AccessSession>
        caption="Access sessions"
        columns={columns}
        rows={q.data?.items}
        rowKey="id"
        loading={q.isPending}
        fetching={q.isFetching}
        error={q.error}
        onRetry={() => void q.refetch()}
        stale={stale}
        emptyTitle="No access sessions"
        emptyDescription="Sessions open when an agent first connects with an approved grant."
        pagination={{
          pageSize: PAGE_SIZE,
          hasPreviousPage: pager.hasPrevious,
          hasNextPage: Boolean(q.data?.next_cursor),
          onPreviousPage: pager.previous,
          onNextPage: () => {
            pager.next(q.data?.next_cursor);
          },
        }}
      />
    </>
  );
}

function GrantsTable({ search, onSearchChange }: SessionsPageProps) {
  const filters = {
    ...(search.state ? { state: search.state as NonNullable<GrantFilters['state']> } : {}),
    ...(search.agent_id ? { agent_id: search.agent_id } : {}),
    ...(search.server_id ? { server_id: search.server_id } : {}),
  };
  const pager = useCursorPager(JSON.stringify(filters));
  const q = useQuery(
    grantListQueryOptions({
      ...filters,
      limit: PAGE_SIZE,
      ...(pager.cursor ? { cursor: pager.cursor } : {}),
    }),
  );
  const stale = useStale();
  const columns: TableColumnsType<Grant> = [
    {
      key: 'id',
      title: 'Grant',
      render: (_, g) => (
        <code className="hp-mono" title={g.id}>
          {shortId(g.id)}
        </code>
      ),
    },
    { key: 'starts', title: 'Started', render: (_, g) => formatDateTime(g.starts_at) },
    { key: 'agent', title: 'Agent', render: (_, g) => <AgentName id={g.agent_id} /> },
    { key: 'server', title: 'Server', render: (_, g) => <ServerName id={g.server_id} /> },
    { key: 'role', title: 'Role', render: (_, g) => <RoleName id={g.role_id} /> },
    { key: 'state', title: 'State', render: (_, g) => <StateBadge kind="grant" state={g.state} /> },
    {
      key: 'expires',
      title: 'Ends',
      render: (_, g) =>
        g.state === 'active' ? (
          <Countdown deadline={g.expires_at} />
        ) : (
          formatDateTime(g.ended_at ?? g.expires_at)
        ),
    },
    { key: 'reason', title: 'End reason', render: (_, g) => orDash(g.end_reason) },
    {
      key: 'session',
      title: 'Session',
      render: (_, g) =>
        g.session_id ? (
          <Link to="/sessions/$id" params={{ id: g.session_id }}>
            Open session
          </Link>
        ) : (
          'Not connected yet'
        ),
    },
    { key: 'actions', title: 'Actions', render: (_, g) => <RevokeGrantButton grant={g} size="small" /> },
  ];
  return (
    <>
      <Filters search={search} states={GRANT_STATES} onSearchChange={onSearchChange} table="grants" />
      <DataTable<Grant>
        caption="Grants"
        columns={columns}
        rows={q.data?.items}
        rowKey="id"
        loading={q.isPending}
        fetching={q.isFetching}
        error={q.error}
        onRetry={() => void q.refetch()}
        stale={stale}
        emptyTitle="No grants"
        emptyDescription="Grants are created when a request is approved."
        pagination={{
          pageSize: PAGE_SIZE,
          hasPreviousPage: pager.hasPrevious,
          hasNextPage: Boolean(q.data?.next_cursor),
          onPreviousPage: pager.previous,
          onNextPage: () => {
            pager.next(q.data?.next_cursor);
          },
        }}
      />
    </>
  );
}

/** `/sessions`: access sessions and grants (WP20; HP-UI-003, HP-UI-008). */
export function SessionsPage({ search, onSearchChange }: SessionsPageProps) {
  const { can, loading } = usePermissions();
  if (loading) {
    return null;
  }
  const canSessions = can('sessions.read');
  const canGrants = can('requests.read');
  if (!canSessions && !canGrants) {
    return (
      <>
        <PageHeader title="Sessions" />
        <PermissionDenied />
      </>
    );
  }
  const tab: SessionsTab = search.tab === 'grants' || !canSessions ? 'grants' : 'sessions';
  const items = [
    ...(canSessions
      ? [
          {
            key: 'sessions',
            label: 'Access sessions',
            children: <SessionsTable search={search} onSearchChange={onSearchChange} />,
          },
        ]
      : []),
    ...(canGrants
      ? [
          {
            key: 'grants',
            label: 'Grants',
            children: <GrantsTable search={search} onSearchChange={onSearchChange} />,
          },
        ]
      : []),
  ];
  return (
    <>
      <PageHeader
        title="Sessions"
        description="Access sessions opened by approved grants, and the grants themselves."
      />
      <Card>
        <Tabs
          activeKey={tab}
          destroyOnHidden
          onChange={(key) => {
            onSearchChange(key === 'grants' ? { tab: 'grants' } : {});
          }}
          items={items}
        />
      </Card>
    </>
  );
}
