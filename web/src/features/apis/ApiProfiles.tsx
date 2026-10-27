import { EditOutlined, PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Card, Dropdown, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { serverRolesQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Role } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { EnabledBadge } from '../agents/AgentsPage';
import { FormModal } from '../servers/FormModal';
import { LifecycleActions } from '../servers/LifecycleActions';
import { DurationText } from '../servers/ServerRoles';
import { ApiCredentialPanel } from './ApiCredentialPanel';
import { ApiProfileFields } from './ApiProfileFields';
import {
  apiProfileDefaults,
  apiProfileFormValues,
  ruleSummary,
  toApiProfileInput,
  type ApiProfileFormValues,
} from './apiForm';
import type { ApiPreset, ProfileTemplate } from './presets';

/** Access profiles of an API target: which requests agents may make, and the credential HallPass adds. */
export function ApiProfiles({
  serverId,
  canWrite,
  preset,
}: {
  serverId: string;
  canWrite: boolean;
  preset: ApiPreset;
}) {
  const queryClient = useQueryClient();
  const query = useQuery(serverRolesQueryOptions(serverId));
  const [creating, setCreating] = useState<ProfileTemplate | null>(null);
  const [editing, setEditing] = useState<Role | null>(null);

  const refresh = async () => {
    await queryClient.invalidateQueries({ queryKey: qk.serverRoles(serverId) });
    await queryClient.invalidateQueries({ queryKey: qk.effectiveAccess });
  };

  return (
    <Card
      size="small"
      title="Access profiles"
      extra={
        canWrite ? (
          <Dropdown
            menu={{
              items: preset.templates.map((t) => ({ key: t.id, label: t.name })),
              onClick: ({ key }) => {
                setCreating(preset.templates.find((t) => t.id === key) ?? null);
              },
            }}
          >
            <Button size="small" icon={<PlusOutlined />}>
              New access profile
            </Button>
          </Dropdown>
        ) : null
      }
    >
      <DataTable<Role>
        caption="Access profiles"
        rowKey="id"
        rows={query.data?.items}
        loading={query.isPending}
        fetching={query.isFetching}
        error={query.error}
        onRetry={() => void query.refetch()}
        emptyTitle="No access profiles"
        emptyDescription="A profile says which requests agents may make and holds the credential HallPass adds to them."
        expandable={{
          expandedRowRender: (r) => (
            <ApiCredentialPanel
              roleId={r.id}
              canWrite={canWrite && !r.deleted_at}
              defaultType={preset.credentialType}
              hint={preset.credentialHint}
            />
          ),
        }}
        columns={[
          {
            key: 'alias',
            title: 'Profile',
            render: (_, r) => (
              <Space orientation="vertical" size={0}>
                <strong>{r.alias}</strong>
                {r.description ? (
                  <span
                    className="hp-legend"
                    style={{ display: 'block', maxWidth: 320, whiteSpace: 'normal' }}
                  >
                    {r.description}
                  </span>
                ) : null}
              </Space>
            ),
          },
          {
            key: 'rules',
            title: 'Rules',
            render: (_, r) => (
              <Space orientation="vertical" size={2}>
                {(r.api?.rules ?? []).map((rule, i) => (
                  <code key={i} className="hp-mono">
                    {ruleSummary(rule)}
                  </code>
                ))}
              </Space>
            ),
          },
          { key: 'max', title: 'Maximum', render: (_, r) => <DurationText seconds={r.max_duration} /> },
          { key: 'enabled', title: 'Status', render: (_, r) => <EnabledBadge enabled={r.enabled} /> },
          {
            key: 'actions',
            title: <span className="hp-visually-hidden">Actions</span>,
            render: (_, r) =>
              canWrite ? (
                <Space wrap size={8}>
                  <Button
                    size="small"
                    icon={<EditOutlined />}
                    aria-label={`Edit ${r.alias}`}
                    onClick={() => {
                      setEditing(r);
                    }}
                  >
                    Edit
                  </Button>
                  <LifecycleActions kind="API profile" target={r} size="small" compact />
                </Space>
              ) : null,
          },
        ]}
      />
      <FormModal<ApiProfileFormValues>
        open={creating !== null}
        title={creating ? `New access profile: ${creating.name}` : 'New access profile'}
        okText="Create profile"
        formLabel="New access profile"
        width={760}
        initialValues={creating ? { ...apiProfileDefaults(creating.rules), alias: creating.id } : undefined}
        onCancel={() => {
          setCreating(null);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          await api.call('post', '/api/v1/servers/{id}/roles', {
            path: { id: serverId },
            body: toApiProfileInput(values),
            idempotencyKey,
          });
          await refresh();
          setCreating(null);
        }}
      >
        <ApiProfileFields />
      </FormModal>
      <FormModal<ApiProfileFormValues>
        open={editing !== null}
        title={editing ? `Edit ${editing.alias}` : 'Edit profile'}
        okText="Save profile"
        formLabel="Edit access profile"
        width={760}
        initialValues={editing ? apiProfileFormValues(editing) : undefined}
        onCancel={() => {
          setEditing(null);
        }}
        onSubmit={async (values) => {
          if (!editing) {
            return;
          }
          await api.call('patch', '/api/v1/roles/{id}', {
            path: { id: editing.id },
            body: toApiProfileInput(values),
            ifMatch: editing.version,
          });
          await refresh();
          setEditing(null);
        }}
      >
        <ApiProfileFields />
      </FormModal>
    </Card>
  );
}
