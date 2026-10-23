import './sessions.css';

import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Alert, Card, Space } from 'antd';
import type { TableColumnsType } from 'antd';

import {
  grantQueryOptions,
  requestQueryOptions,
  sessionChannelsQueryOptions,
  sessionQueryOptions,
  sessionSegmentsQueryOptions,
} from '../../api/queries';
import type { Channel, Segment } from '../../api/types';
import { Countdown } from '../../ds/Countdown';
import { DataTable } from '../../ds/DataTable';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { UntrustedText } from '../../ds/UntrustedText';
import { orDash } from './text';
import { formatBytes, formatDateTime, formatDuration, shortId } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { AgentName, RoleName, ServerName } from '../../shared/names';
import { channelKind, reasonText } from '../../shared/channelClose';
import { ChannelEndCell, GatewayExitLegend } from '../../shared/ChannelEnd';
import { StateBadge } from '../../shared/StateBadge';
import { DestinationRecords } from './DestinationRecords';
import { ExportButton } from './ExportButton';
import { RevokeGrantButton } from './GrantActions';
import { ReplayPanel } from './replay/ReplayPanel';
import { SessionTimeline } from './timeline/SessionTimeline';

function Mono({ value }: { value: string | null | undefined }) {
  return value ? <code className="hp-mono">{value}</code> : <>—</>;
}

function GrantPanel({ grantId }: { grantId: string }) {
  const { can } = usePermissions();
  const grant = useQuery({ ...grantQueryOptions(grantId), enabled: can('requests.read') });
  const requestId = grant.data?.request_id;
  const request = useQuery({ ...requestQueryOptions(requestId ?? ''), enabled: Boolean(requestId) });
  if (!can('requests.read')) {
    return <p>Grant details need the requests.read permission.</p>;
  }
  if (grant.isPending) {
    return <LoadingState label="Loading grant…" />;
  }
  if (grant.isError) {
    return <ErrorState error={grant.error} onRetry={() => void grant.refetch()} />;
  }
  const g = grant.data;
  let reason: React.ReactNode = '—';
  if (request.data?.has_reason) {
    reason =
      request.data.reason !== null && request.data.reason !== undefined ? (
        <UntrustedText text={request.data.reason} source="the agent" block />
      ) : (
        'Provided, but your role cannot read request reasons (requests.reason.read).'
      );
  } else if (request.isPending && requestId) {
    reason = 'Loading…';
  }
  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <KeyValueGrid
        items={[
          { key: 'state', label: 'State', value: <StateBadge kind="grant" state={g.state} /> },
          {
            key: 'remaining',
            label: g.state === 'active' ? 'Remaining' : 'Ended',
            value:
              g.state === 'active' ? (
                <Countdown deadline={g.expires_at} />
              ) : (
                formatDateTime(g.ended_at ?? g.expires_at)
              ),
          },
          { key: 'starts', label: 'Started', value: formatDateTime(g.starts_at) },
          { key: 'expires', label: 'Expires', value: formatDateTime(g.expires_at) },
          {
            key: 'caps',
            label: 'Capabilities',
            value: g.capabilities && g.capabilities.length > 0 ? g.capabilities.join(', ') : '—',
          },
          { key: 'user', label: 'Remote user', value: <Mono value={g.remote_user} /> },
          { key: 'end', label: 'End reason', value: reasonText(g.end_reason) ?? '—' },
          { key: 'policy', label: 'Policy version', value: g.policy_version ?? '—' },
          {
            key: 'request',
            label: 'Request',
            value: (
              <Link to="/requests/$id" params={{ id: g.request_id }}>
                <code className="hp-mono">{shortId(g.request_id)}</code>
              </Link>
            ),
          },
          {
            key: 'requested',
            label: 'Requested duration',
            value: request.data ? formatDuration(request.data.requested_duration) : '—',
          },
          { key: 'reason', label: 'Agent reason', value: reason, span: 'full' },
        ]}
      />
      <div>
        <RevokeGrantButton grant={g} />
      </div>
    </Space>
  );
}

function ChannelsTable({ sessionId }: { sessionId: string }) {
  const q = useQuery(sessionChannelsQueryOptions(sessionId));
  const columns: TableColumnsType<Channel> = [
    {
      key: 'id',
      title: 'Channel',
      render: (_, c) => (
        <code className="hp-mono" title={c.id}>
          {shortId(c.id)}
        </code>
      ),
    },
    { key: 'kind', title: 'Kind', render: (_, c) => channelKind(c) },
    { key: 'state', title: 'State', render: (_, c) => <StateBadge kind="channel" state={c.state} /> },
    { key: 'opened', title: 'Opened', render: (_, c) => formatDateTime(c.opened_at) },
    { key: 'closed', title: 'Closed', render: (_, c) => (c.closed_at ? formatDateTime(c.closed_at) : '—') },
    {
      key: 'exit',
      title: 'Exit',
      render: (_, c) =>
        c.exit_signal
          ? `signal ${c.exit_signal}`
          : c.exit_status !== null && c.exit_status !== undefined
            ? String(c.exit_status)
            : '—',
    },
    { key: 'reason', title: 'Why it ended', render: (_, c) => <ChannelEndCell channel={c} /> },
    {
      key: 'connection',
      title: 'Connection',
      render: (_, c) => (
        <code className="hp-mono" title={c.connection_id}>
          {shortId(c.connection_id)}
        </code>
      ),
    },
  ];
  return (
    <DataTable<Channel>
      caption="Channels"
      columns={columns}
      rows={q.data?.items}
      rowKey="id"
      loading={q.isPending}
      error={q.error}
      onRetry={() => void q.refetch()}
      emptyTitle="No channels"
      emptyDescription="The agent has not opened a shell or exec channel in this session."
      footer={
        q.data?.items.some((c) => c.gateway_exit_code !== null && c.gateway_exit_code !== undefined) ? (
          <GatewayExitLegend />
        ) : undefined
      }
    />
  );
}

function SegmentsTable({
  segments,
  loading,
  error,
  onRetry,
}: {
  segments: Segment[] | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
}) {
  const columns: TableColumnsType<Segment> = [
    {
      key: 'channel',
      title: 'Channel',
      render: (_, s) => (
        <code className="hp-mono" title={s.channel_id}>
          {shortId(s.channel_id)}
        </code>
      ),
    },
    { key: 'ordinal', title: 'Segment', dataIndex: 'ordinal' },
    { key: 'state', title: 'State', render: (_, s) => <StateBadge kind="segment" state={s.state} /> },
    { key: 'records', title: 'Records', render: (_, s) => s.records ?? '—' },
    { key: 'bytes', title: 'Size', render: (_, s) => formatBytes(s.bytes) },
    {
      key: 'seq',
      title: 'Seq range',
      render: (_, s) =>
        s.first_seq !== null && s.first_seq !== undefined
          ? `${String(s.first_seq)}–${String(s.last_seq ?? '?')}`
          : '—',
    },
    { key: 'verify', title: 'Integrity check', render: (_, s) => orDash(s.verify_result, 'Not checked yet') },
    { key: 'end', title: 'End reason', render: (_, s) => orDash(s.end_reason) },
    { key: 'opened', title: 'Opened', render: (_, s) => formatDateTime(s.opened_at) },
    {
      key: 'final',
      title: 'Finalized',
      render: (_, s) => (s.finalized_at ? formatDateTime(s.finalized_at) : '—'),
    },
  ];
  return (
    <DataTable<Segment>
      caption="Recording segments"
      columns={columns}
      rows={segments}
      rowKey="id"
      loading={loading}
      error={error}
      onRetry={onRetry}
      emptyTitle="No recording segments"
    />
  );
}

/** `/sessions/$id`: access-session detail (HP-UI-004) with unified timeline and per-channel replay (WP21). */
export function SessionDetailPage({ id }: { id: string }) {
  const { can, loading } = usePermissions();
  const session = useQuery({ ...sessionQueryOptions(id), enabled: can('sessions.read') });
  const channels = useQuery({ ...sessionChannelsQueryOptions(id), enabled: can('sessions.read') });
  const segments = useQuery({ ...sessionSegmentsQueryOptions(id), enabled: can('sessions.read') });

  const back = <Link to="/sessions">← Sessions</Link>;
  if (loading) {
    return null;
  }
  if (!can('sessions.read')) {
    return (
      <>
        <PageHeader title="Access session" above={back} />
        <PermissionDenied />
      </>
    );
  }
  if (session.isPending) {
    return (
      <>
        <PageHeader title="Access session" above={back} />
        <LoadingState />
      </>
    );
  }
  if (session.isError) {
    return (
      <>
        <PageHeader title="Access session" above={back} />
        <ErrorState error={session.error} onRetry={() => void session.refetch()} />
      </>
    );
  }
  const s = session.data;
  const segs = segments.data?.items;
  const segmentProblems = (segs ?? []).filter(
    (x) => x.state === 'interrupted' || x.state === 'missing' || x.state === 'failed',
  );

  return (
    <>
      <PageHeader
        title="Access session"
        above={back}
        description={
          <>
            <code className="hp-mono">{s.id}</code>
          </>
        }
        extra={<ExportButton sessionId={s.id} />}
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {segmentProblems.length > 0 ? (
          <Alert
            type="warning"
            showIcon
            title="Recording integrity warning"
            description={`${String(segmentProblems.length)} recording segment(s) are ${[...new Set(segmentProblems.map((x) => x.state))].join(', ')}.`}
          />
        ) : null}
        <Card title="Summary" size="small">
          <KeyValueGrid
            items={[
              { key: 'state', label: 'State', value: <StateBadge kind="session" state={s.state} /> },
              { key: 'agent', label: 'Agent', value: <AgentName id={s.agent_id} /> },
              { key: 'server', label: 'Server', value: <ServerName id={s.server_id} /> },
              { key: 'role', label: 'Role', value: <RoleName id={s.role_id} /> },
              { key: 'user', label: 'Remote user', value: <Mono value={s.remote_user} /> },
              { key: 'grant', label: 'Grant', value: <StateBadge kind="grant" state={s.grant_state} /> },
              {
                key: 'remaining',
                label: 'Grant remaining',
                value: s.grant_state === 'active' ? <Countdown deadline={s.grant_expires_at} /> : '—',
              },
              { key: 'opened', label: 'Opened', value: formatDateTime(s.opened_at) },
              { key: 'closed', label: 'Closed', value: s.closed_at ? formatDateTime(s.closed_at) : '—' },
              { key: 'close', label: 'Close reason', value: reasonText(s.close_reason) ?? '—' },
              {
                key: 'channels',
                label: 'Channels (live / total)',
                value:
                  s.channels_total !== undefined
                    ? `${String(s.channels_live ?? 0)} / ${String(s.channels_total)}`
                    : '—',
              },
              { key: 'retention', label: 'Retention class', value: s.retention_class },
              {
                key: 'delete',
                label: 'Delete after',
                value: s.delete_after ? formatDateTime(s.delete_after) : '—',
              },
            ]}
          />
        </Card>
        <Card title="Grant and request" size="small">
          <GrantPanel grantId={s.grant_id} />
        </Card>
        <Card title="Channels" size="small">
          <ChannelsTable sessionId={s.id} />
        </Card>
        <Card title="Recording segments" size="small">
          <SegmentsTable
            segments={segs}
            loading={segments.isPending}
            error={segments.error}
            onRetry={() => void segments.refetch()}
          />
        </Card>
        <Card title="Replay" size="small">
          {can('recording.play') ? (
            channels.isPending || segments.isPending ? (
              <LoadingState />
            ) : channels.isError || segments.isError ? (
              <ErrorState
                error={channels.error ?? segments.error}
                onRetry={() => {
                  void channels.refetch();
                  void segments.refetch();
                }}
              />
            ) : (
              <ReplayPanel channels={channels.data.items} segments={segments.data.items} />
            )
          ) : (
            <Alert
              type="info"
              showIcon
              title="Replay needs the recording.play permission"
              description="Ask an administrator if you need to review this session's terminal output."
            />
          )}
        </Card>
        <Card title="Destination-reported commands" size="small">
          <DestinationRecords sessionId={s.id} />
        </Card>
        <Card title="Timeline" size="small">
          <SessionTimeline sessionId={s.id} />
        </Card>
      </Space>
    </>
  );
}
