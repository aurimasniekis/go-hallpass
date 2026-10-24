import { EditOutlined, PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { serverRolesQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Role } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { EnabledBadge } from '../agents/AgentsPage';
import { CredentialsPanel } from '../credentials/CredentialsPanel';
import { FormModal } from '../servers/FormModal';
import { DurationText } from '../servers/ServerRoles';
import { GitProfileFields } from './GitProfileFields';
import {
  GIT_PROFILE_DEFAULTS,
  gitProfileFormValues,
  pushSummary,
  toGitProfileInput,
  type GitProfileFormValues,
} from './gitForm';

/** Access profiles of a git remote: which repositories and refs agents may use, and each profile's login key. */
export function GitProfiles({
  serverId,
  canWrite,
  keyHint,
}: {
  serverId: string;
  canWrite: boolean;
  keyHint: string;
}) {
  const queryClient = useQueryClient();
  const query = useQuery(serverRolesQueryOptions(serverId));
  const [creating, setCreating] = useState(false);
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
          <Button
            size="small"
            icon={<PlusOutlined />}
            onClick={() => {
              setCreating(true);
            }}
          >
            New access profile
          </Button>
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
        emptyDescription="A profile says which repositories agents may clone or push, and carries the key HallPass logs in with."
        expandable={{
          expandedRowRender: (r) => (
            <Space orientation="vertical" size={12} style={{ width: '100%' }}>
              <Alert type="info" showIcon title="Installing the login key" description={keyHint} />
              <CredentialsPanel roleId={r.id} gitRemote />
            </Space>
          ),
        }}
        columns={[
          {
            key: 'alias',
            title: 'Profile',
            render: (_, r) => (
              <Space orientation="vertical" size={0}>
                <strong>{r.alias}</strong>
                {r.description ? <span className="hp-legend">{r.description}</span> : null}
              </Space>
            ),
          },
          {
            key: 'repos',
            title: 'Repositories',
            render: (_, r) => (
              <Space size={4} wrap>
                {(r.git?.repos ?? []).map((p) => (
                  <code key={p} className="hp-mono">
                    {p}
                  </code>
                ))}
              </Space>
            ),
          },
          { key: 'push', title: 'Push', render: (_, r) => pushSummary(r) },
          { key: 'max', title: 'Maximum', render: (_, r) => <DurationText seconds={r.max_duration} /> },
          { key: 'enabled', title: 'Status', render: (_, r) => <EnabledBadge enabled={r.enabled} /> },
          {
            key: 'actions',
            title: <span className="hp-visually-hidden">Actions</span>,
            render: (_, r) =>
              canWrite ? (
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
              ) : null,
          },
        ]}
      />
      <FormModal<GitProfileFormValues>
        open={creating}
        title="New access profile"
        okText="Create profile"
        formLabel="New access profile"
        width={680}
        initialValues={GIT_PROFILE_DEFAULTS}
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          await api.call('post', '/api/v1/servers/{id}/roles', {
            path: { id: serverId },
            body: toGitProfileInput(values),
            idempotencyKey,
          });
          await refresh();
          setCreating(false);
        }}
      >
        <GitProfileFields />
      </FormModal>
      <FormModal<GitProfileFormValues>
        open={editing !== null}
        title={editing ? `Edit ${editing.alias}` : 'Edit profile'}
        okText="Save profile"
        formLabel="Edit access profile"
        width={680}
        initialValues={editing ? gitProfileFormValues(editing) : undefined}
        onCancel={() => {
          setEditing(null);
        }}
        onSubmit={async (values) => {
          if (!editing) {
            return;
          }
          await api.call('patch', '/api/v1/roles/{id}', {
            path: { id: editing.id },
            body: toGitProfileInput(values),
            ifMatch: editing.version,
          });
          await refresh();
          setEditing(null);
        }}
      >
        <GitProfileFields />
      </FormModal>
    </Card>
  );
}
