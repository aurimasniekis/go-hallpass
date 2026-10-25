import { useQuery } from '@tanstack/react-query';
import { Card, Space } from 'antd';

import { gatewayHostKeysQueryOptions, systemStatusQueryOptions } from '../../api/queries';
import { CopyField } from '../../ds/CopyField';
import { Fingerprint } from '../../ds/Fingerprint';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { formatDateTime } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { SshBansCard } from './SshBans';
import { SystemControls } from './SystemControls';
import { ResponsiveTable } from '../../ds/DataTable';

/** Settings → System: health, version, lockdown controls and gateway host keys (PLAN §14.3, §18.17). */
export function SystemPage() {
  const { can, loading } = usePermissions();
  const status = useQuery({ ...systemStatusQueryOptions(), enabled: can('dashboard.view') });
  const keys = useQuery({ ...gatewayHostKeysQueryOptions(), enabled: can('dashboard.view') });
  if (loading) {
    return <LoadingState />;
  }
  if (!can('dashboard.view')) {
    return (
      <>
        <PageHeader title="System" />
        <PermissionDenied />
      </>
    );
  }
  return (
    <>
      <PageHeader title="System" description="Health, emergency lockdown, SSH bans and gateway host keys." />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card title="Status" size="small">
          {status.isPending ? (
            <LoadingState />
          ) : status.isError ? (
            <ErrorState error={status.error} onRetry={() => void status.refetch()} />
          ) : (
            <KeyValueGrid
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
                {
                  key: 'storage',
                  label: 'Storage',
                  value: status.data.storage_ok ? (
                    <StatusBadge tone="success">Accepting writes</StatusBadge>
                  ) : (
                    <StatusBadge tone="error">Degraded</StatusBadge>
                  ),
                },
                {
                  key: 'breakglass',
                  label: 'Break-glass recovery',
                  value: status.data.breakglass_alert ? (
                    <StatusBadge tone="warning">
                      Used {status.data.breakglass_at ? formatDateTime(status.data.breakglass_at) : ''}, not
                      acknowledged
                    </StatusBadge>
                  ) : (
                    'No unacknowledged use'
                  ),
                },
                {
                  key: 'version',
                  label: 'Version',
                  value: <code className="hp-mono">{status.data.version}</code>,
                },
                {
                  span: 2,
                  key: 'boot',
                  label: 'Boot ID',
                  value: <code className="hp-mono">{status.data.boot_id}</code>,
                },
                { key: 'policy', label: 'Policy version', value: status.data.policy_version ?? '—' },
                { key: 'pending', label: 'Pending requests', value: status.data.pending_requests },
                { key: 'grants', label: 'Active grants', value: status.data.active_grants },
                { key: 'live', label: 'Live channels', value: status.data.live_channels },
              ]}
            />
          )}
        </Card>
        <SystemControls />
        <SshBansCard />
        <Card title="Gateway host keys" size="small">
          <p className="hp-card-intro">
            Agents pin these keys in <code className="hp-mono">known_hosts</code> before connecting. They are
            public and not secret.
          </p>
          {keys.isPending ? (
            <LoadingState />
          ) : keys.isError ? (
            <ErrorState error={keys.error} onRetry={() => void keys.refetch()} />
          ) : (
            <ResponsiveTable
              size="small"
              pagination={false}
              rowKey="id"
              dataSource={keys.data.items}
              scroll={{ x: 'max-content' }}
              columns={[
                { key: 'alg', title: 'Algorithm', render: (_v, k) => k.algorithm },
                { key: 'fp', title: 'Fingerprint', render: (_v, k) => <Fingerprint value={k.fingerprint} /> },
                { key: 'state', title: 'State', render: (_v, k) => k.state },
                { key: 'created', title: 'Created', render: (_v, k) => formatDateTime(k.created_at) },
                {
                  key: 'key',
                  title: 'Public key',
                  render: (_v, k) => (
                    <div style={{ minWidth: 'min(280px, 100%)' }}>
                      <CopyField label={`${k.algorithm} public key`} value={k.public_key} hideLabel />
                    </div>
                  ),
                },
              ]}
            />
          )}
        </Card>
      </Space>
    </>
  );
}
