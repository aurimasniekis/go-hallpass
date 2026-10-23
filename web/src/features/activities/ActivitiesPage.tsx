import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { App, Card } from 'antd';

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
import { StateBadge } from '../../shared/StateBadge';
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

/** Live channels across active sessions (HP-SES-005). SSE `channel` events refresh the list. */
export function ActivitiesPage() {
  const { can, loading } = usePermissions();
  const q = useQuery({ ...activitiesQueryOptions(), enabled: can('sessions.read') });
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
  return (
    <>
      <PageHeader title="Activities" description="Live channels across active sessions." />
      <Card size="small">
        <DataTable<Channel>
          caption="Live channels"
          rowKey="id"
          rows={q.data?.items}
          loading={q.isPending}
          fetching={q.isFetching}
          error={q.error}
          onRetry={() => void q.refetch()}
          stale={sse.status === 'stale' || sse.status === 'disconnected'}
          emptyTitle="No live channels"
          emptyDescription="Channels appear here while agents are connected."
          columns={[
            { key: 'agent', title: 'Agent', render: (_v, c) => <AgentName id={c.agent_id} /> },
            { key: 'role', title: 'Role', render: (_v, c) => <RoleName id={c.role_id} /> },
            { key: 'kind', title: 'Kind', render: (_v, c) => c.kind },
            { key: 'pty', title: 'PTY', render: (_v, c) => (c.pty ? 'Yes' : 'No') },
            {
              key: 'state',
              title: 'State',
              render: (_v, c) => <StateBadge kind="channel" state={c.state} />,
            },
            {
              key: 'opened',
              title: 'Opened',
              render: (_v, c) => (
                <span title={formatDateTime(c.opened_at)}>{formatRelative(c.opened_at, now)}</span>
              ),
            },
            {
              key: 'session',
              title: 'Session',
              render: (_v, c) => (
                <Link to="/sessions/$id" params={{ id: c.session_id }} title={c.session_id}>
                  {shortId(c.session_id)}
                </Link>
              ),
            },
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
                    render: (_v: unknown, c: Channel) => <TerminateButton channel={c} />,
                  },
                ]
              : []),
          ]}
        />
      </Card>
    </>
  );
}
