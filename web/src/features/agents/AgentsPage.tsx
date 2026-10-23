import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Button, Card, Input, Space, Tag } from 'antd';
import { useMemo, useState } from 'react';

import { api } from '../../api/client';
import { agentsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Agent } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { formatDateTime } from '../../lib/format';
import { labelsToTags } from '../../lib/labels';
import { usePermissions } from '../../lib/usePermissions';
import { useSseState } from '../../stores/sse';
import { FormModal } from '../servers/FormModal';
import { AgentFormFields } from './AgentFormFields';
import { toAgentCreate, type AgentFormValues } from './agentForm';

export function TagList({ values }: { values: readonly string[] | null | undefined }) {
  if (!values || values.length === 0) {
    return <>—</>;
  }
  return (
    <Space size={4} wrap>
      {values.map((v) => (
        <Tag key={v}>{v}</Tag>
      ))}
    </Space>
  );
}

export function EnabledBadge({ enabled }: { enabled: boolean }) {
  return <StatusBadge tone={enabled ? 'success' : 'neutral'}>{enabled ? 'Enabled' : 'Disabled'}</StatusBadge>;
}

/** Agents list (PLAN §14.3, §18.3): identity of AI agents that connect over SSH. */
export function AgentsPage() {
  const { can, loading } = usePermissions();
  const query = useQuery({ ...agentsQueryOptions(), enabled: can('inventory.read') });
  const sse = useSseState();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState(false);

  const rows = useMemo(() => {
    const term = search.trim().toLowerCase();
    const items = query.data?.items;
    if (!items || term === '') {
      return items;
    }
    return items.filter(
      (a) =>
        a.name.toLowerCase().includes(term) ||
        a.description.toLowerCase().includes(term) ||
        (a.groups ?? []).some((g) => g.toLowerCase().includes(term)),
    );
  }, [query.data, search]);

  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Agents" />
        <PermissionDenied />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Agents"
        description="AI agents that connect to the gateway with their own SSH keys."
        extra={
          can('inventory.write') ? (
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                setCreating(true);
              }}
            >
              New agent
            </Button>
          ) : null
        }
      />
      <Card size="small">
        <Space style={{ marginBottom: 12 }}>
          <Input.Search
            aria-label="Filter agents"
            placeholder="Filter by name, description or group"
            allowClear
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
            }}
            style={{ width: 320 }}
          />
        </Space>
        <DataTable<Agent>
          caption="Agents"
          rowKey="id"
          rows={rows}
          loading={query.isPending}
          fetching={query.isFetching}
          error={query.error}
          onRetry={() => void query.refetch()}
          stale={sse.status === 'stale' || sse.status === 'disconnected'}
          emptyTitle={search ? 'No matching agents' : 'No agents yet'}
          emptyDescription={search ? undefined : 'Create an agent and add its public key to let it connect.'}
          columns={[
            {
              key: 'name',
              title: 'Name',
              render: (_, a) => (
                <Link to="/agents/$id" params={{ id: a.id }}>
                  {a.name}
                </Link>
              ),
            },
            { key: 'description', title: 'Description', dataIndex: 'description', ellipsis: true },
            { key: 'enabled', title: 'Status', render: (_, a) => <EnabledBadge enabled={a.enabled} /> },
            { key: 'groups', title: 'Groups', render: (_, a) => <TagList values={a.groups} /> },
            { key: 'labels', title: 'Labels', render: (_, a) => <TagList values={labelsToTags(a.labels)} /> },
            {
              key: 'cidrs',
              title: 'Source CIDRs',
              render: (_, a) => (a.source_cidrs?.length ? <TagList values={a.source_cidrs} /> : 'Any'),
            },
            { key: 'updated', title: 'Updated', render: (_, a) => formatDateTime(a.updated_at) },
          ]}
        />
      </Card>
      <FormModal<AgentFormValues>
        open={creating}
        title="New agent"
        okText="Create agent"
        formLabel="New agent"
        initialValues={{ enabled: true }}
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          const agent = await api.call('post', '/api/v1/agents', {
            body: toAgentCreate(values),
            idempotencyKey,
          });
          await queryClient.invalidateQueries({ queryKey: qk.agents });
          setCreating(false);
          void navigate({ to: '/agents/$id', params: { id: agent.id } });
        }}
      >
        <AgentFormFields mode="create" />
      </FormModal>
    </>
  );
}
