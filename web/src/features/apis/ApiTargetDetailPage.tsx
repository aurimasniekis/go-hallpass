import { EditOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Alert, Button, Card, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { apiTargetCAQueryOptions, serverQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import { CopyField } from '../../ds/CopyField';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { EnabledBadge } from '../agents/AgentsPage';
import { EffectiveAccessCard } from '../servers/EffectiveAccessTable';
import { FormModal } from '../servers/FormModal';
import { orDash } from '../servers/formUtils';
import { LifecycleActions } from '../servers/LifecycleActions';
import { ApiProfiles } from './ApiProfiles';
import { ApiHostsField } from './ApiTargetsPage';
import { CUSTOM_PRESET, presetForHosts } from './presets';

function CACard({ serverId }: { serverId: string }) {
  const query = useQuery(apiTargetCAQueryOptions(serverId));
  return (
    <Card size="small" title="Proxy CA">
      {query.isPending ? (
        <LoadingState />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : (
        <Space orientation="vertical" size={12} style={{ width: '100%' }}>
          <span className="hp-legend">
            Agents trust this CA for this API&apos;s hosts only (it cannot sign any other name or an IP
            address). They get it with <code className="hp-mono">ssh center api ca</code>.
          </span>
          <KeyValueGrid
            items={[
              {
                key: 'fp',
                label: 'SHA-256',
                span: 'full',
                value: <code className="hp-mono">{query.data.fingerprint}</code>,
              },
              { key: 'names', label: 'Permitted names', value: (query.data.permitted_dns ?? []).join(', ') },
              { key: 'until', label: 'Valid until', value: formatDateTime(query.data.not_after) },
            ]}
          />
          <CopyField label="Certificate (PEM)" value={query.data.certificate} />
        </Space>
      )}
    </Card>
  );
}

/** One API target: its hosts, proxy CA, access profiles (rules and credentials) and who may use which profile. */
export function ApiTargetDetailPage({ id }: { id: string }) {
  const { can, loading } = usePermissions();
  const query = useQuery({ ...serverQueryOptions(id), enabled: can('inventory.read') });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [editingHosts, setEditingHosts] = useState(false);
  const back = <Link to="/apis">← APIs</Link>;
  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="API target" above={back} />
        <PermissionDenied />
      </>
    );
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader title="API target" above={back} />
        <LoadingState />
      </>
    );
  }
  if (query.isError) {
    return (
      <>
        <PageHeader title="API target" above={back} />
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      </>
    );
  }
  const target = query.data;
  const hosts = target.api?.hosts ?? [];
  const preset = presetForHosts(hosts) ?? CUSTOM_PRESET;
  const canWrite = can('inventory.write') && !target.deleted_at;
  return (
    <>
      <PageHeader
        title={target.alias}
        above={back}
        description={(target.description ?? '').length > 0 ? target.description : preset.name}
        extra={
          canWrite ? (
            <Space wrap>
              <Button
                icon={<EditOutlined />}
                onClick={() => {
                  setEditingHosts(true);
                }}
              >
                Edit hosts
              </Button>
              <LifecycleActions
                kind="API target"
                target={target}
                onDeleted={() => {
                  void navigate({ to: '/apis' });
                }}
              />
            </Space>
          ) : null
        }
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {target.deleted_at ? (
          <Alert
            type="warning"
            showIcon
            title={`Deleted ${formatDateTime(target.deleted_at)}`}
            description="Kept only so past sessions and the audit log can name it. Agents cannot reach it."
          />
        ) : null}
        <KeyValueGrid
          items={[
            { key: 'api', label: 'API', value: preset.name },
            {
              key: 'hosts',
              label: 'Hosts',
              span: 2,
              value:
                hosts.length > 0 ? (
                  <Space size={4} wrap>
                    {hosts.map((h) => (
                      <code key={h} className="hp-mono">
                        {h}
                      </code>
                    ))}
                  </Space>
                ) : (
                  'Hidden (needs address access)'
                ),
            },
            { key: 'status', label: 'Status', value: <EnabledBadge enabled={target.enabled} /> },
            {
              span: 2,
              key: 'request',
              label: 'Agents request with',
              value: (
                <code className="hp-mono">
                  ssh center request {target.alias} --role &lt;profile&gt; --reason &apos;…&apos;
                </code>
              ),
            },
            { key: 'desc', label: 'Description', value: orDash(target.description) },
            { key: 'updated', label: 'Updated', value: formatDateTime(target.updated_at) },
          ]}
        />
        {!target.deleted_at ? <CACard serverId={id} /> : null}
        <ApiProfiles serverId={id} canWrite={canWrite} preset={preset} />
        {can('policy.read') ? <EffectiveAccessCard kind="server" id={id} /> : null}
      </Space>
      <FormModal<{ hosts: string[] }>
        open={editingHosts}
        title="Edit hosts"
        okText="Save hosts"
        formLabel="API target hosts"
        width={600}
        initialValues={{ hosts }}
        onCancel={() => {
          setEditingHosts(false);
        }}
        onSubmit={async (values) => {
          await api.call('patch', '/api/v1/servers/{id}', {
            path: { id },
            body: { api: { hosts: values.hosts.map((h) => h.trim().toLowerCase()) } },
            ifMatch: target.version,
          });
          await queryClient.invalidateQueries({ queryKey: qk.server(id) });
          await queryClient.invalidateQueries({ queryKey: qk.apiTargetCA(id) });
          await queryClient.invalidateQueries({ queryKey: qk.servers });
          setEditingHosts(false);
        }}
      >
        <ApiHostsField />
      </FormModal>
    </>
  );
}
