import { RocketOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Alert, Button, Card, Space, Tabs } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { serverQueryOptions, serverRolesQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { labelsToTags } from '../../lib/labels';
import { usePermissions } from '../../lib/usePermissions';
import { EnabledBadge, TagList } from '../agents/AgentsPage';
import { DestinationCollectors } from './DestinationCollectors';
import { EffectiveAccessCard } from './EffectiveAccessTable';
import { FormModal } from './FormModal';
import { LifecycleActions } from './LifecycleActions';
import { orDash } from './formUtils';
import { HostCAPanel } from './HostCA';
import { HostIdentities } from './HostIdentities';
import { needsOnboarding } from './onboarding/model';
import { ServerFormFields } from './ServerFormFields';
import { serverFormValues, toServerInput, type ServerFormValues } from './serverForm';
import { ServerRoles } from './ServerRoles';
import { AddressCell } from './ServersPage';

export const SERVER_TABS = ['overview', 'identities', 'roles', 'access', 'collectors'] as const;
export type ServerTab = (typeof SERVER_TABS)[number];

export function ServerDetailPage({
  id,
  tab = 'overview',
  onTabChange,
}: {
  id: string;
  tab?: ServerTab;
  onTabChange?: (tab: ServerTab) => void;
}) {
  const { can, loading } = usePermissions();
  const queryClient = useQueryClient();
  const query = useQuery({ ...serverQueryOptions(id), enabled: can('inventory.read') });
  const roles = useQuery({ ...serverRolesQueryOptions(id), enabled: can('inventory.read') });
  const [editing, setEditing] = useState(false);
  const navigate = useNavigate();
  const canWrite = can('inventory.write');
  const canAddress = can('inventory.address.read');

  const back = <Link to="/servers">← Servers</Link>;
  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Server" above={back} />
        <PermissionDenied />
      </>
    );
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader title="Server" above={back} />
        <LoadingState />
      </>
    );
  }
  if (query.isError) {
    return (
      <>
        <PageHeader title="Server" above={back} />
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      </>
    );
  }
  const server = query.data;

  const deleted = Boolean(server.deleted_at);
  const setupIncomplete = !deleted && needsOnboarding(server, roles.data?.items);
  const overview = (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      {server.deleted_at ? (
        <Alert
          type="warning"
          showIcon
          title={`Deleted ${formatDateTime(server.deleted_at)}`}
          description="Kept only so past sessions and the audit log can name it. Agents cannot reach it."
        />
      ) : null}
      {setupIncomplete && canWrite ? (
        <Alert
          type="warning"
          showIcon
          title="Setup is not finished"
          description={
            (server.active_host_identities ?? 0) === 0 && !server.host_ca_id
              ? 'The gateway cannot verify this host yet, so agents cannot connect. Continue the guided setup to confirm a host key, add roles and install login credentials.'
              : 'This server has no roles yet, so agents cannot request access. Continue the guided setup to add roles and login credentials.'
          }
          action={
            <Link to="/servers/onboard" search={{ server: server.id }}>
              Continue guided setup
            </Link>
          }
        />
      ) : null}
      <Alert
        type="info"
        showIcon
        title="Descriptions and labels are informational"
        description="They help people and policy selectors find this server, but never enforce anything themselves; access is decided by policy rules and the roles below."
      />
      <Card size="small" title="Details">
        <KeyValueGrid
          items={[
            { span: 2, key: 'id', label: 'Server ID', value: <code className="hp-mono">{server.id}</code> },
            { key: 'name', label: 'Display name', value: server.display_name },
            { span: 2, key: 'desc', label: 'Description', value: orDash(server.description) },
            { key: 'env', label: 'Environment', value: orDash(server.environment) },
            { key: 'addr', label: 'Address', value: <AddressCell server={server} /> },
            { key: 'status', label: 'Status', value: <EnabledBadge enabled={server.enabled} /> },
            { key: 'groups', label: 'Groups', value: <TagList values={server.groups} /> },
            { key: 'labels', label: 'Labels', value: <TagList values={labelsToTags(server.labels)} /> },
            { key: 'meta', label: 'Metadata', value: <TagList values={labelsToTags(server.metadata)} /> },
            {
              key: 'hostids',
              label: 'Active host identities',
              value: server.active_host_identities ?? '—',
            },
            { key: 'version', label: 'Version', value: server.version },
            { key: 'created', label: 'Created', value: formatDateTime(server.created_at) },
            { key: 'updated', label: 'Updated', value: formatDateTime(server.updated_at) },
          ]}
        />
      </Card>
      <HostCAPanel server={server} canWrite={canWrite} />
    </Space>
  );

  return (
    <>
      <PageHeader
        above={back}
        title={server.alias}
        description={server.display_name !== server.alias ? server.display_name : undefined}
        extra={
          canWrite && !deleted ? (
            <Space wrap>
              <Button
                icon={<RocketOutlined />}
                onClick={() => {
                  void navigate({ to: '/servers/onboard', search: { server: server.id } });
                }}
              >
                Guided setup
              </Button>
              <Button
                onClick={() => {
                  setEditing(true);
                }}
              >
                Edit
              </Button>
              <LifecycleActions
                kind="server"
                target={server}
                onDeleted={() => {
                  void navigate({ to: '/servers' });
                }}
              />
            </Space>
          ) : null
        }
      />
      <Tabs
        activeKey={tab}
        onChange={(key) => onTabChange?.(key as ServerTab)}
        items={[
          { key: 'overview', label: 'Overview', children: overview },
          {
            key: 'identities',
            label: 'Host identities',
            children: canAddress ? (
              <HostIdentities serverId={id} canWrite={canWrite} />
            ) : (
              <PermissionDenied detail="Host identities reveal destination details and need the inventory.address.read permission." />
            ),
          },
          { key: 'roles', label: 'Roles', children: <ServerRoles serverId={id} canWrite={canWrite} /> },
          {
            key: 'access',
            label: 'Effective access',
            children: can('policy.read') ? (
              <EffectiveAccessCard kind="server" id={id} />
            ) : (
              <PermissionDenied detail="Effective access needs the policy.read permission." />
            ),
          },
          {
            key: 'collectors',
            label: 'Destination audit',
            children: <DestinationCollectors serverId={id} canManage={can('credentials.manage')} />,
          },
        ]}
      />
      <FormModal<ServerFormValues>
        open={editing}
        title="Edit server"
        okText="Save"
        formLabel="Edit server"
        initialValues={serverFormValues(server)}
        onCancel={() => {
          setEditing(false);
        }}
        onSubmit={async (values) => {
          await api.call('patch', '/api/v1/servers/{id}', {
            path: { id },
            body: toServerInput(values, {
              includeAddress: canAddress && !server.address_redacted,
              version: server.version,
            }),
            ifMatch: server.version,
          });
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: qk.server(id) }),
            queryClient.invalidateQueries({ queryKey: qk.servers }),
            queryClient.invalidateQueries({ queryKey: qk.effectiveAccess }),
          ]);
          setEditing(false);
        }}
      >
        <ServerFormFields mode="edit" showAddress={canAddress && !server.address_redacted} />
      </FormModal>
    </>
  );
}
