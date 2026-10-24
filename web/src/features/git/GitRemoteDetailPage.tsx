import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Alert, Space } from 'antd';

import { serverQueryOptions } from '../../api/queries';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { EnabledBadge } from '../agents/AgentsPage';
import { EffectiveAccessCard } from '../servers/EffectiveAccessTable';
import { orDash } from '../servers/formUtils';
import { LifecycleActions } from '../servers/LifecycleActions';
import { HostIdentities } from '../servers/HostIdentities';
import { AddressCell } from '../servers/ServersPage';
import { GitProfiles } from './GitProfiles';
import { CUSTOM_KEY_HINT, presetFor } from './presets';

/** One git remote: its pinned host keys, access profiles (with login keys) and who may use which profile. */
export function GitRemoteDetailPage({ id }: { id: string }) {
  const { can, loading } = usePermissions();
  const query = useQuery({ ...serverQueryOptions(id), enabled: can('inventory.read') });
  const navigate = useNavigate();
  const back = <Link to="/git">← Git</Link>;
  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Git remote" above={back} />
        <PermissionDenied />
      </>
    );
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader title="Git remote" above={back} />
        <LoadingState />
      </>
    );
  }
  if (query.isError) {
    return (
      <>
        <PageHeader title="Git remote" above={back} />
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      </>
    );
  }
  const remote = query.data;
  const preset = presetFor(remote.address);
  const canWrite = can('inventory.write') && !remote.deleted_at;
  return (
    <>
      <PageHeader
        title={remote.alias}
        above={back}
        description={(remote.description ?? '').length > 0 ? remote.description : preset?.name}
        extra={
          canWrite ? (
            <LifecycleActions
              kind="git remote"
              target={remote}
              onDeleted={() => {
                void navigate({ to: '/git' });
              }}
            />
          ) : null
        }
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {remote.deleted_at ? (
          <Alert
            type="warning"
            showIcon
            title={`Deleted ${formatDateTime(remote.deleted_at)}`}
            description="Kept only so past sessions and the audit log can name it. Agents cannot reach it."
          />
        ) : null}
        <KeyValueGrid
          items={[
            { key: 'host', label: 'Git host', value: preset?.name ?? 'Other host' },
            { key: 'addr', label: 'Address', value: <AddressCell server={remote} /> },
            { key: 'status', label: 'Status', value: <EnabledBadge enabled={remote.enabled} /> },
            {
              span: 2,
              key: 'url',
              label: 'Agents clone with',
              value: (
                <code className="hp-mono">
                  git clone center:{remote.alias}/&lt;owner&gt;/&lt;repository&gt;.git
                </code>
              ),
            },
            { key: 'desc', label: 'Description', value: orDash(remote.description) },
            { key: 'updated', label: 'Updated', value: formatDateTime(remote.updated_at) },
          ]}
        />
        <HostIdentities
          serverId={id}
          canWrite={canWrite}
          {...(preset
            ? {
                published: {
                  name: preset.name,
                  fingerprints: preset.fingerprints,
                  url: preset.fingerprintsUrl,
                },
              }
            : {})}
        />
        <GitProfiles serverId={id} canWrite={canWrite} keyHint={preset?.keyHint ?? CUSTOM_KEY_HINT} />
        {can('policy.read') ? <EffectiveAccessCard kind="server" id={id} /> : null}
      </Space>
    </>
  );
}
