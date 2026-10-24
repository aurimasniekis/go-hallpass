import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Alert, Button, Card, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { roleQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionGate } from '../../ds/PermissionGate';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { labelsToTags } from '../../lib/labels';
import { usePermissions } from '../../lib/usePermissions';
import { ServerName } from '../../shared/names';
import { EnabledBadge, TagList } from '../agents/AgentsPage';
import { CertBindingPanel } from '../credentials/CertBindingPanel';
import { CredentialsPanel } from '../credentials/CredentialsPanel';
import { UserCAsPanel } from '../credentials/UserCAsPanel';
import { FormModal } from '../servers/FormModal';
import { orDash } from '../servers/formUtils';
import { DurationText } from '../servers/ServerRoles';
import { RoleFormFields } from './RoleFormFields';
import { roleFormValues, toRoleInput, type RoleFormValues } from './roleForm';

/** Role detail (PLAN §14.3 `/roles/$id`): role limits, login identity and destination credentials. */
export function RoleDetailPage({ id }: { id: string }) {
  const { can, loading } = usePermissions();
  const queryClient = useQueryClient();
  // Detail pages read fresh data (the shared role query is long-lived for name lookups).
  const query = useQuery({ ...roleQueryOptions(id), staleTime: 0, enabled: can('inventory.read') });
  const [editing, setEditing] = useState(false);

  const back = <Link to="/servers">← Servers</Link>;
  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Role" above={back} />
        <PermissionDenied />
      </>
    );
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader title="Role" above={back} />
        <LoadingState />
      </>
    );
  }
  if (query.isError) {
    return (
      <>
        <PageHeader title="Role" above={back} />
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      </>
    );
  }
  const role = query.data;
  const serverLink = (
    <Link to="/servers/$id" params={{ id: role.server_id }} search={{ tab: 'roles' }}>
      ← <ServerName id={role.server_id} link={false} /> roles
    </Link>
  );

  return (
    <>
      <PageHeader
        above={serverLink}
        title={`Role ${role.alias}`}
        description={
          <>
            Logs in as <code className="hp-mono">{role.remote_user}</code> on{' '}
            <ServerName id={role.server_id} />
          </>
        }
        extra={
          can('inventory.write') ? (
            <Button
              onClick={() => {
                setEditing(true);
              }}
            >
              Edit
            </Button>
          ) : null
        }
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card size="small" title="Settings">
          <KeyValueGrid
            items={[
              { span: 2, key: 'id', label: 'Role ID', value: <code className="hp-mono">{role.id}</code> },
              { key: 'name', label: 'Display name', value: orDash(role.display_name) },
              { span: 2, key: 'desc', label: 'Description', value: orDash(role.description) },
              { key: 'status', label: 'Status', value: <EnabledBadge enabled={role.enabled} /> },
              { key: 'caps', label: 'Capabilities', value: <TagList values={role.capabilities} /> },
              {
                key: 'default',
                label: 'Default duration',
                value: <DurationText seconds={role.default_duration} />,
              },
              { key: 'max', label: 'Maximum duration', value: <DurationText seconds={role.max_duration} /> },
              {
                key: 'conc',
                label: 'Concurrency',
                value: `${String(role.max_concurrent ?? '—')} total, ${String(role.max_concurrent_per_agent ?? '—')} per agent`,
              },
              {
                key: 'rec',
                label: 'Recording',
                value: role.recording_mode === 'best_effort' ? 'Best effort' : 'Mandatory',
              },
              {
                key: 'input',
                label: 'Input recording',
                value: role.record_input ? 'On — input may contain secrets' : 'Off',
              },
              {
                key: 'channels',
                label: 'Approval channels',
                value: <TagList values={role.approval_channels} />,
              },
              { key: 'env', label: 'Allowed environment', value: <TagList values={role.env_allow} /> },
              { key: 'retention', label: 'Retention class', value: orDash(role.retention_class) },
              { key: 'labels', label: 'Labels', value: <TagList values={labelsToTags(role.labels)} /> },
              { span: 2, key: 'notes', label: 'Restriction notes', value: orDash(role.restriction_notes) },
              { key: 'version', label: 'Version', value: role.version },
              { key: 'updated', label: 'Updated', value: formatDateTime(role.updated_at ?? null) },
            ]}
          />
          {role.record_input ? (
            <Alert
              style={{ marginTop: 12 }}
              type="warning"
              showIcon
              title="Keyboard input is recorded for this role"
              description="Input may contain secrets typed at prompts; HallPass does not redact them (HP-REC-005)."
            />
          ) : null}
        </Card>
        <PermissionGate
          permission="credentials.manage"
          fallback={
            <Card size="small" title="Login credentials">
              <p style={{ margin: 0 }}>
                Managing destination login keys and certificates needs the credentials.manage permission
                (administrators).
              </p>
            </Card>
          }
        >
          <CredentialsPanel roleId={id} />
          <div style={{ height: 16 }} />
          <CertBindingPanel roleId={id} remoteUser={role.remote_user} />
          <div style={{ height: 16 }} />
          <UserCAsPanel />
        </PermissionGate>
      </Space>
      <FormModal<RoleFormValues>
        open={editing}
        title="Edit role"
        okText="Save"
        formLabel="Edit role"
        width={680}
        initialValues={roleFormValues(role)}
        onCancel={() => {
          setEditing(false);
        }}
        onSubmit={async (values) => {
          await api.call('patch', '/api/v1/roles/{id}', {
            path: { id },
            body: toRoleInput(values, role.version),
            ifMatch: role.version,
          });
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: qk.role(id) }),
            queryClient.invalidateQueries({ queryKey: qk.serverRoles(role.server_id) }),
            queryClient.invalidateQueries({ queryKey: qk.effectiveAccess }),
          ]);
          setEditing(false);
        }}
      >
        <RoleFormFields />
      </FormModal>
    </>
  );
}
