import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Card, Col, Row, Segmented, Space } from 'antd';
import { useState } from 'react';

import {
  activitiesQueryOptions,
  grantListQueryOptions,
  requestListQueryOptions,
  statsOverviewQueryOptions,
  systemStatusQueryOptions,
  type StatsRange,
} from '../../api/queries';
import type { AccessRequest, Channel, Grant } from '../../api/types';
import { ChartCard } from '../../ds/ChartCard';
import { Countdown } from '../../ds/Countdown';
import { DataTable } from '../../ds/DataTable';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { StatusBadge, type StatusTone } from '../../ds/StatusBadge';
import { formatDateTime, formatDuration, formatRelative } from '../../lib/format';
import { useNow } from '../../lib/useNow';
import { usePermissions } from '../../lib/usePermissions';
import { AgentName, RoleName, ServerName } from '../../shared/names';
import { channelKind } from '../../shared/channelClose';
import { StateBadge } from '../../shared/StateBadge';
import { useSseState, type SseStatus } from '../../stores/sse';
import { BreakGlassAck, LockdownControls } from './LockdownControls';
import {
  barOption,
  isAllZero,
  lineOption,
  seriesSummary,
  seriesTable,
  stateEntries,
  stateSummary,
} from './stats';

const SSE_LABEL: Record<SseStatus, [StatusTone, string]> = {
  idle: ['neutral', 'Not started'],
  connecting: ['processing', 'Connecting'],
  connected: ['success', 'Connected'],
  reconnecting: ['warning', 'Reconnecting'],
  stale: ['warning', 'Stale'],
  disconnected: ['error', 'Disconnected'],
};

const RANGES: { value: StatsRange; label: string }[] = [
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
];

function SystemStatusCard() {
  const status = useQuery(systemStatusQueryOptions());
  return (
    <Card title="System status" size="small" extra={<LockdownControls status={status.data} />}>
      {status.isPending ? (
        <LoadingState />
      ) : status.isError ? (
        <ErrorState error={status.error} onRetry={() => void status.refetch()} />
      ) : (
        <KeyValueGrid
          columns={4}
          items={[
            {
              key: 'lockdown',
              label: 'Lockdown',
              value: status.data.lockdown ? (
                <StatusBadge tone="error">Active</StatusBadge>
              ) : (
                <StatusBadge tone="success">Off</StatusBadge>
              ),
            },
            { key: 'pending', label: 'Pending requests', value: status.data.pending_requests },
            { key: 'grants', label: 'Active grants', value: status.data.active_grants },
            { key: 'live', label: 'Live channels', value: status.data.live_channels },
            {
              key: 'storage',
              label: 'Storage',
              value: status.data.storage_ok ? (
                <StatusBadge tone="success">Accepting writes</StatusBadge>
              ) : (
                <StatusBadge tone="error">Not accepting writes</StatusBadge>
              ),
            },
            { key: 'policy', label: 'Policy version', value: status.data.policy_version ?? '—' },
            { key: 'version', label: 'HallPass version', value: status.data.version },
            {
              key: 'breakglass',
              label: 'Break-glass',
              value: status.data.breakglass_alert ? (
                <Space wrap>
                  <StatusBadge tone="warning">
                    Used {formatDateTime(status.data.breakglass_at ?? null)}
                  </StatusBadge>
                  <BreakGlassAck />
                </Space>
              ) : (
                'No unacknowledged use'
              ),
            },
          ]}
        />
      )}
    </Card>
  );
}

function PendingRequestsCard() {
  const q = useQuery(requestListQueryOptions({ state: 'pending', limit: 10 }));
  return (
    <Card
      title="Pending requests"
      size="small"
      extra={
        <Link to="/requests" search={{ state: 'pending' }}>
          View all
        </Link>
      }
    >
      <DataTable<AccessRequest>
        caption="Pending requests"
        rowKey="id"
        rows={q.data?.items}
        loading={q.isPending}
        error={q.error}
        onRetry={() => void q.refetch()}
        emptyTitle="No pending requests"
        columns={[
          {
            key: 'agent',
            title: 'Agent',
            render: (_v, r) => <AgentName id={r.agent_id} />,
          },
          { key: 'server', title: 'Server', render: (_v, r) => <ServerName id={r.server_id} /> },
          { key: 'role', title: 'Role', render: (_v, r) => <RoleName id={r.role_id} /> },
          { key: 'dur', title: 'Duration', render: (_v, r) => formatDuration(r.requested_duration) },
          { key: 'expires', title: 'Expires in', render: (_v, r) => <Countdown deadline={r.expires_at} /> },
          {
            key: 'open',
            title: <span className="hp-visually-hidden">Actions</span>,
            render: (_v, r) => (
              <Link to="/requests/$id" params={{ id: r.id }} aria-label={`Review request ${r.id}`}>
                Review
              </Link>
            ),
          },
        ]}
      />
    </Card>
  );
}

function ActiveGrantsCard() {
  const q = useQuery(grantListQueryOptions({ state: 'active', limit: 10 }));
  return (
    <Card title="Active grants" size="small" extra={<Link to="/sessions">Sessions</Link>}>
      <DataTable<Grant>
        caption="Active grants"
        rowKey="id"
        rows={q.data?.items}
        loading={q.isPending}
        error={q.error}
        onRetry={() => void q.refetch()}
        emptyTitle="No active grants"
        columns={[
          { key: 'agent', title: 'Agent', render: (_v, g) => <AgentName id={g.agent_id} /> },
          { key: 'server', title: 'Server', render: (_v, g) => <ServerName id={g.server_id} /> },
          {
            key: 'user',
            title: 'Remote user',
            render: (_v, g) => <code className="hp-mono">{g.remote_user}</code>,
          },
          { key: 'left', title: 'Remaining', render: (_v, g) => <Countdown deadline={g.expires_at} /> },
          {
            key: 'session',
            title: 'Session',
            render: (_v, g) =>
              g.session_id ? (
                <Link to="/sessions/$id" params={{ id: g.session_id }}>
                  Open
                </Link>
              ) : (
                'Not connected'
              ),
          },
        ]}
      />
    </Card>
  );
}

function LiveActivitiesCard() {
  const q = useQuery(activitiesQueryOptions());
  const now = useNow(15_000);
  return (
    <Card
      title={`Live activities${q.data ? ` (${String(q.data.items.length)})` : ''}`}
      size="small"
      extra={<Link to="/activities">View all</Link>}
    >
      <DataTable<Channel>
        caption="Live activities"
        rowKey="id"
        rows={q.data?.items.slice(0, 10)}
        loading={q.isPending}
        error={q.error}
        onRetry={() => void q.refetch()}
        emptyTitle="No live channels"
        columns={[
          { key: 'agent', title: 'Agent', render: (_v, c) => <AgentName id={c.agent_id} /> },
          { key: 'role', title: 'Role', render: (_v, c) => <RoleName id={c.role_id} /> },
          { key: 'kind', title: 'Kind', render: (_v, c) => channelKind(c) },
          { key: 'state', title: 'State', render: (_v, c) => <StateBadge kind="channel" state={c.state} /> },
          {
            key: 'opened',
            title: 'Opened',
            render: (_v, c) => (
              <span title={formatDateTime(c.opened_at)}>{formatRelative(c.opened_at, now)}</span>
            ),
          },
        ]}
      />
    </Card>
  );
}

function StatsCharts() {
  const [range, setRange] = useState<StatsRange>('24h');
  const stats = useQuery(statsOverviewQueryOptions(range));
  const data = stats.data;
  const bucket = data?.bucket_seconds ?? 3600;
  const loading = stats.isPending;
  const error = stats.error ?? undefined;
  const retry = () => void stats.refetch();
  const requests = data?.requests ?? [];
  const sessions = data?.sessions ?? [];
  const states = stateEntries(data?.requests_by_state);
  const rangeSelector = (
    <Segmented<StatsRange>
      aria-label="Chart time range"
      size="small"
      value={range}
      onChange={setRange}
      options={RANGES}
    />
  );
  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>{rangeSelector}</div>
      <Row gutter={[16, 16]} className="hp-equal-cards">
        <Col xs={24} xl={8}>
          <ChartCard
            title="Requests over time"
            summary={seriesSummary('requests', requests, range, bucket)}
            option={lineOption('Requests', requests, bucket)}
            table={seriesTable(requests, bucket, 'Requests')}
            loading={loading}
            error={error}
            onRetry={retry}
            empty={!loading && !error && isAllZero(requests)}
          />
        </Col>
        <Col xs={24} xl={8}>
          <ChartCard
            title="Sessions opened"
            summary={seriesSummary('sessions', sessions, range, bucket)}
            option={lineOption('Sessions', sessions, bucket)}
            table={seriesTable(sessions, bucket, 'Sessions')}
            loading={loading}
            error={error}
            onRetry={retry}
            empty={!loading && !error && isAllZero(sessions)}
          />
        </Col>
        <Col xs={24} xl={8}>
          <ChartCard
            title="Requests by state"
            summary={stateSummary(states, range)}
            option={barOption(states)}
            table={{
              columns: [
                { key: 'state', title: 'State' },
                { key: 'n', title: 'Requests' },
              ],
              rows: states.map(([state, n]) => ({ state, n })),
            }}
            loading={loading}
            error={error}
            onRetry={retry}
            empty={!loading && !error && states.every(([, n]) => n === 0)}
          />
        </Col>
      </Row>
    </Space>
  );
}

function LiveUpdatesCard() {
  const sse = useSseState();
  const [tone, label] = SSE_LABEL[sse.status];
  return (
    <Card title="Live updates" size="small">
      <KeyValueGrid
        items={[
          { key: 'status', label: 'Stream', value: <StatusBadge tone={tone}>{label}</StatusBadge> },
          {
            key: 'last',
            label: 'Last event',
            value:
              sse.lastEventAt === null ? 'None received yet' : new Date(sse.lastEventAt).toLocaleTimeString(),
          },
        ]}
      />
    </Card>
  );
}

/**
 * Dashboard (docs/PLAN.md §14.3/§14.6): system status with lockdown controls, pending requests,
 * active grants, live activities and charts from `GET /stats/overview`. Only real data is shown;
 * each card is hidden when the operator lacks its read permission (the API enforces it anyway).
 */
export function DashboardPage() {
  const { can, loading } = usePermissions();
  if (loading) {
    return <LoadingState />;
  }
  const canDashboard = can('dashboard.view');
  const canRequests = can('requests.read');
  const canSessions = can('sessions.read');
  if (!canDashboard && !canRequests && !canSessions) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <PermissionDenied />
      </>
    );
  }
  return (
    <>
      <PageHeader title="Dashboard" description="Overview of access activity." />
      <Row gutter={[16, 16]} className="hp-equal-cards">
        {canDashboard ? (
          <Col span={24}>
            <SystemStatusCard />
          </Col>
        ) : null}
        {canRequests ? (
          <Col xs={24} xl={12}>
            <PendingRequestsCard />
          </Col>
        ) : null}
        {canRequests ? (
          <Col xs={24} xl={12}>
            <ActiveGrantsCard />
          </Col>
        ) : null}
        {canSessions ? (
          <Col xs={24} xl={12}>
            <LiveActivitiesCard />
          </Col>
        ) : null}
        <Col xs={24} xl={canSessions ? 12 : 24}>
          <LiveUpdatesCard />
        </Col>
        {canDashboard ? (
          <Col span={24}>
            <StatsCharts />
          </Col>
        ) : null}
      </Row>
    </>
  );
}
