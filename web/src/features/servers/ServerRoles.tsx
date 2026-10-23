import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Button, Card, Space, Tag } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { serverRolesQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Role } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { formatDuration, formatDurationLong } from '../../lib/format';
import { EnabledBadge, TagList } from '../agents/AgentsPage';
import { RoleFormFields } from '../roles/RoleFormFields';
import { ROLE_DEFAULTS, toRoleInput, type RoleFormValues } from '../roles/roleForm';
import { FormModal } from './FormModal';

export function DurationText({ seconds }: { seconds: number | null | undefined }) {
  return <span title={formatDurationLong(seconds)}>{formatDuration(seconds)}</span>;
}

/** Roles of one server: the login identity and limits an agent can request (PLAN §5, §18.4). */
export function ServerRoles({ serverId, canWrite }: { serverId: string; canWrite: boolean }) {
  const queryClient = useQueryClient();
  const query = useQuery(serverRolesQueryOptions(serverId));
  const [creating, setCreating] = useState(false);
  return (
    <Card
      size="small"
      title="Roles"
      extra={
        canWrite ? (
          <Button
            size="small"
            icon={<PlusOutlined />}
            onClick={() => {
              setCreating(true);
            }}
          >
            New role
          </Button>
        ) : null
      }
    >
      <DataTable<Role>
        caption="Roles"
        rowKey="id"
        rows={query.data?.items}
        loading={query.isPending}
        fetching={query.isFetching}
        error={query.error}
        onRetry={() => void query.refetch()}
        emptyTitle="No roles"
        emptyDescription="Agents can only request access through a role."
        columns={[
          {
            key: 'alias',
            title: 'Alias',
            render: (_, r) => (
              <Link to="/roles/$id" params={{ id: r.id }}>
                {r.alias}
              </Link>
            ),
          },
          {
            key: 'user',
            title: 'Remote user',
            render: (_, r) => <code className="hp-mono">{r.remote_user}</code>,
          },
          { key: 'caps', title: 'Capabilities', render: (_, r) => <TagList values={r.capabilities} /> },
          {
            key: 'default',
            title: 'Default',
            render: (_, r) => <DurationText seconds={r.default_duration} />,
          },
          { key: 'max', title: 'Maximum', render: (_, r) => <DurationText seconds={r.max_duration} /> },
          {
            key: 'recording',
            title: 'Recording',
            render: (_, r) => (
              <Space size={4} wrap>
                <span>{r.recording_mode === 'best_effort' ? 'Best effort' : 'Mandatory'}</span>
                {r.record_input ? <Tag>input recorded</Tag> : null}
              </Space>
            ),
          },
          { key: 'channels', title: 'Approval', render: (_, r) => <TagList values={r.approval_channels} /> },
          { key: 'enabled', title: 'Status', render: (_, r) => <EnabledBadge enabled={r.enabled} /> },
        ]}
      />
      <FormModal<RoleFormValues>
        open={creating}
        title="New role"
        okText="Create role"
        formLabel="New role"
        width={680}
        initialValues={ROLE_DEFAULTS}
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          await api.call('post', '/api/v1/servers/{id}/roles', {
            path: { id: serverId },
            body: toRoleInput(values),
            idempotencyKey,
          });
          await queryClient.invalidateQueries({ queryKey: qk.serverRoles(serverId) });
          await queryClient.invalidateQueries({ queryKey: qk.effectiveAccess });
          setCreating(false);
        }}
      >
        <RoleFormFields />
      </FormModal>
    </Card>
  );
}
