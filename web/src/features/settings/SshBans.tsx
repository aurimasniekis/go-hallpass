import { useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Card } from 'antd';

import { api } from '../../api/client';
import { sshBansQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { SSHBan } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { Countdown } from '../../ds/Countdown';
import { DataTable } from '../../ds/DataTable';
import { PermissionDenied } from '../../ds/states';
import { revealControls } from '../../ds/untrusted';
import { formatDateTime, formatRelative } from '../../lib/format';
import { useNow } from '../../lib/useNow';
import { usePermissions } from '../../lib/usePermissions';

function LiftBan({ ban }: { ban: SSHBan }) {
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  return (
    <ConfirmAction
      label="Lift"
      title="Lift this SSH ban"
      confirmLabel="Lift ban"
      buttonProps={{ size: 'small', 'aria-label': `Lift ban on ${ban.address}` }}
      description={
        <>
          <p>
            <code className="hp-mono">{ban.address}</code> may connect to the agent SSH port again
            immediately. If it keeps failing authentication it is banned again, for twice as long.
          </p>
          <p style={{ marginBottom: 0 }}>Lifting a ban needs recent authentication and is audited.</p>
        </>
      }
      onConfirm={() => api.call('delete', '/api/v1/ssh-bans/{id}', { path: { id: ban.id } })}
      onSuccess={() => {
        void message.success(`Ban on ${ban.address} lifted.`);
        void queryClient.invalidateQueries({ queryKey: qk.sshBans });
      }}
    />
  );
}

/**
 * fail2ban-style protection of the agent SSH port: sources with repeated failed SSH connections are
 * refused for a while, doubling with every repeat offense. Listing needs system.read; lifting needs
 * system.settings and recent authentication (the client opens the reauth prompt when asked).
 */
export function SshBansCard() {
  const { can } = usePermissions();
  const q = useQuery({ ...sshBansQueryOptions(), enabled: can('system.read') });
  const now = useNow(30_000);
  const canLift = can('system.settings');
  return (
    <Card title="SSH bans" size="small">
      <p className="hp-card-intro">
        Sources that repeatedly fail to authenticate on the agent SSH port are refused until the ban expires.
        Each repeat offense doubles the ban.
      </p>
      {!can('system.read') ? (
        <PermissionDenied detail="Listing SSH bans needs the system.read permission." />
      ) : (
        <DataTable<SSHBan>
          caption="SSH bans"
          rowKey="id"
          rows={q.data?.items}
          loading={q.isPending}
          fetching={q.isFetching}
          error={q.error}
          onRetry={() => void q.refetch()}
          emptyTitle="No active bans"
          emptyDescription="No source is currently banned from the agent SSH port."
          columns={[
            {
              key: 'address',
              title: 'Source',
              render: (_v, b) => <code className="hp-mono">{b.address}</code>,
            },
            { key: 'failures', title: 'Failures', align: 'right', render: (_v, b) => b.failures },
            {
              key: 'offense',
              title: 'Offense',
              align: 'right',
              render: (_v, b) => (b.offense ? `#${String(b.offense)}` : '—'),
            },
            { key: 'reason', title: 'Reason', render: (_v, b) => revealControls(b.reason) || '—' },
            {
              key: 'banned',
              title: 'Banned',
              render: (_v, b) => (
                <span title={formatDateTime(b.banned_at)}>{formatRelative(b.banned_at, now)}</span>
              ),
            },
            {
              key: 'expires',
              title: 'Expires in',
              render: (_v, b) => <Countdown deadline={b.expires_at} expiredLabel="Expired" />,
            },
            ...(canLift
              ? [
                  {
                    key: 'actions',
                    title: <span className="hp-visually-hidden">Actions</span>,
                    align: 'right' as const,
                    render: (_v: unknown, b: SSHBan) => <LiftBan ban={b} />,
                  },
                ]
              : []),
          ]}
        />
      )}
    </Card>
  );
}
