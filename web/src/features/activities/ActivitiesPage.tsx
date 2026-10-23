import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { App, Card, Segmented, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { activitiesQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Channel } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { LoadingState, PermissionDenied } from '../../ds/states';
import { formatDateTime, formatRelative, shortId } from '../../lib/format';
import { useNow } from '../../lib/useNow';
import { usePermissions } from '../../lib/usePermissions';
import { AgentName, RoleName } from '../../shared/names';
import { ChannelEndCell, GatewayExitLegend } from '../../shared/ChannelEnd';
import { StateBadge } from '../../shared/StateBadge';
import { channelKind } from '../../shared/channelClose';
import { useSseState } from '../../stores/sse';

/** Message for the 202 `{terminated}` answer: the server says whether a live channel was found. */
export function terminateOutcome(terminated: boolean): string {
  return terminated
    ? 'Termination requested. The channel closes as soon as the gateway tears it down.'
    : 'The channel had already ended; nothing was terminated.';
}

function TerminateButton({ channel }: { channel: Channel }) {
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  return (
    <ConfirmAction<{ terminated: boolean }>
      label="Terminate"
      title="Terminate this activity"
      confirmLabel="Terminate"
      buttonProps={{ size: 'small', 'aria-label': `Terminate channel ${channel.id}` }}
      description="The live channel is closed immediately. The grant stays active; revoke it from the session to stop new channels."
      onConfirm={({ idempotencyKey }) =>
        api.call('post', '/api/v1/activities/{id}/terminate', { path: { id: channel.id }, idempotencyKey })
      }
      onSuccess={(res) => {
        void (res.terminated ? message.success : message.info)(terminateOutcome(res.terminated));
        void queryClient.invalidateQueries({ queryKey: qk.activities });
        void queryClient.invalidateQueries({ queryKey: qk.accessSessionRoot });
      }}
    />
  );
}

const ENDED_WINDOWS = [
  { value: 3_600, label: '1 hour' },
  { value: 86_400, label: '24 hours' },
  { value: 7 * 86_400, label: '7 days' },
] as const;

function SessionLink({ id }: { id: string }) {
  return (
    <Link to="/sessions/$id" params={{ id }} title={id}>
      {shortId(id)}
    </Link>
  );
}

/** Live channels across active sessions (HP-SES-005), plus recently ended ones with why they ended. */
export function ActivitiesPage() {
  const { can, loading } = usePermissions();
  const [endedSince, setEndedSince] = useState<number>(86_400);
  const q = useQuery({ ...activitiesQueryOptions(), enabled: can('sessions.read') });
  const ended = useQuery({ ...activitiesQueryOptions(endedSince), enabled: can('sessions.read') });
  const sse = useSseState();
  const now = useNow(10_000);
  if (loading) {
    return <LoadingState />;
  }
  if (!can('sessions.read')) {
    return (
      <>
        <PageHeader title="Activities" />
        <PermissionDenied />
      </>
    );
  }
  const canTerminate = can('activities.terminate');
  const stale = sse.status === 'stale' || sse.status === 'disconnected';
  const endedRows = ended.data?.items
    .filter((c) => Boolean(c.closed_at) || (c.state !== 'active' && c.state !== 'opening'))
    .sort((a, b) => (b.closed_at ?? b.opened_at).localeCompare(a.closed_at ?? a.opened_at));
  const relative = (iso: string | null | undefined) =>
    iso ? <span title={formatDateTime(iso)}>{formatRelative(iso, now)}</span> : '—';
  return (
    <>
      <PageHeader
        title="Activities"
        description="Live channels across active sessions, and channels that ended recently with the reason."
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card size="small" title="Live channels">
          <DataTable<Channel>
            caption="Live channels"
            rowKey="id"
            rows={q.data?.items.filter((c) => !c.closed_at)}
            loading={q.isPending}
            fetching={q.isFetching}
            error={q.error}
            onRetry={() => void q.refetch()}
            stale={stale}
            emptyTitle="No live channels"
            emptyDescription="Channels appear here while agents are connected."
            columns={[
              { key: 'agent', title: 'Agent', render: (_v, c) => <AgentName id={c.agent_id} /> },
              { key: 'role', title: 'Role', render: (_v, c) => <RoleName id={c.role_id} /> },
              { key: 'kind', title: 'Kind', render: (_v, c) => channelKind(c) },
              {
                key: 'state',
                title: 'State',
                render: (_v, c) => <StateBadge kind="channel" state={c.state} />,
              },
              { key: 'opened', title: 'Opened', render: (_v, c) => relative(c.opened_at) },
              { key: 'session', title: 'Session', render: (_v, c) => <SessionLink id={c.session_id} /> },
              {
                key: 'connection',
                title: 'Connection',
                render: (_v, c) => (
                  <code className="hp-mono" title={c.connection_id}>
                    {shortId(c.connection_id)}
                  </code>
                ),
              },
              ...(canTerminate
                ? [
                    {
                      key: 'actions',
                      title: <span className="hp-visually-hidden">Actions</span>,
                      align: 'right' as const,
                      render: (_v: unknown, c: Channel) => <TerminateButton channel={c} />,
                    },
                  ]
                : []),
            ]}
          />
        </Card>
        <Card
          size="small"
          title="Recently ended"
          extra={
            <Segmented<number>
              size="small"
              aria-label="Ended within"
              value={endedSince}
              onChange={setEndedSince}
              options={ENDED_WINDOWS.map((w) => ({ value: w.value, label: w.label }))}
            />
          }
        >
          <DataTable<Channel>
            caption="Recently ended channels"
            rowKey="id"
            rows={endedRows}
            loading={ended.isPending}
            fetching={ended.isFetching}
            error={ended.error}
            onRetry={() => void ended.refetch()}
            stale={stale}
            emptyTitle="No channels ended in this window"
            emptyDescription="Closed, failed and terminated channels are listed here (at most 200)."
            footer={
              endedRows?.some((c) => c.gateway_exit_code !== null && c.gateway_exit_code !== undefined) ? (
                <GatewayExitLegend />
              ) : undefined
            }
            columns={[
              { key: 'agent', title: 'Agent', render: (_v, c) => <AgentName id={c.agent_id} /> },
              { key: 'role', title: 'Role', render: (_v, c) => <RoleName id={c.role_id} /> },
              { key: 'kind', title: 'Kind', render: (_v, c) => channelKind(c) },
              {
                key: 'state',
                title: 'State',
                render: (_v, c) => <StateBadge kind="channel" state={c.state} />,
              },
              { key: 'closed', title: 'Ended', render: (_v, c) => relative(c.closed_at) },
              {
                key: 'exit',
                title: 'Exit',
                render: (_v, c) =>
                  c.exit_signal
                    ? `signal ${c.exit_signal}`
                    : c.exit_status !== null && c.exit_status !== undefined
                      ? String(c.exit_status)
                      : '—',
              },
              { key: 'why', title: 'Why it ended', render: (_v, c) => <ChannelEndCell channel={c} /> },
              { key: 'session', title: 'Session', render: (_v, c) => <SessionLink id={c.session_id} /> },
            ]}
          />
        </Card>
      </Space>
    </>
  );
}
