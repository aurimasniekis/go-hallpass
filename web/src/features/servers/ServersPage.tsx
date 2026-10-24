import { PlusOutlined, RocketOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Button, Card, Input, Space } from 'antd';
import { useMemo, useState } from 'react';

import { api } from '../../api/client';
import { serversQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Server } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { labelsToTags } from '../../lib/labels';
import { usePermissions } from '../../lib/usePermissions';
import { useSseState } from '../../stores/sse';
import { EnabledBadge, TagList } from '../agents/AgentsPage';
import { FormModal } from './FormModal';
import { orDash } from './formUtils';
import { ServerFormFields } from './ServerFormFields';
import { serverAddress, toServerInput, type ServerFormValues } from './serverForm';

export function AddressCell({ server }: { server: Pick<Server, 'address' | 'port' | 'address_redacted'> }) {
  const address = serverAddress(server);
  return address ? (
    <code className="hp-mono">{address}</code>
  ) : (
    <span title="Requires the inventory.address.read permission">Hidden</span>
  );
}

/** Destination servers (PLAN §14.3, §18.4). */
export function ServersPage() {
  const { can, loading } = usePermissions();
  const query = useQuery({ ...serversQueryOptions(), enabled: can('inventory.read') });
  const sse = useSseState();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState(false);
  const showAddress = can('inventory.address.read');

  const rows = useMemo(() => {
    const term = search.trim().toLowerCase();
    // Git remotes have their own page.
    const items = query.data?.items.filter((s) => s.kind !== 'git');
    if (!items || term === '') {
      return items;
    }
    return items.filter((s) =>
      [s.alias, s.display_name, s.environment ?? '', ...(s.groups ?? [])].some((v) =>
        v.toLowerCase().includes(term),
      ),
    );
  }, [query.data, search]);

  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Servers" />
        <PermissionDenied />
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Servers"
        description="Destination hosts, their verified host identities and the roles agents can request."
        extra={
          can('inventory.write') ? (
            <Space wrap>
              <Button
                icon={<PlusOutlined />}
                onClick={() => {
                  setCreating(true);
                }}
              >
                New server
              </Button>
              <Button
                type="primary"
                icon={<RocketOutlined />}
                onClick={() => {
                  void navigate({ to: '/servers/onboard' });
                }}
              >
                New server (guided)
              </Button>
            </Space>
          ) : null
        }
      />
      <Card size="small">
        <Space style={{ marginBottom: 12 }}>
          <Input.Search
            aria-label="Filter servers"
            placeholder="Filter by alias, name, environment or group"
            allowClear
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
            }}
            style={{ width: 320 }}
          />
        </Space>
        <DataTable<Server>
          caption="Servers"
          rowKey="id"
          rows={rows}
          loading={query.isPending}
          fetching={query.isFetching}
          error={query.error}
          onRetry={() => void query.refetch()}
          stale={sse.status === 'stale' || sse.status === 'disconnected'}
          emptyTitle={search ? 'No matching servers' : 'No servers yet'}
          emptyDescription={search ? undefined : 'Add a server, enroll its host key, then create a role.'}
          columns={[
            {
              key: 'alias',
              title: 'Alias',
              render: (_, s) => (
                <Link to="/servers/$id" params={{ id: s.id }}>
                  {s.alias}
                </Link>
              ),
            },
            { key: 'name', title: 'Display name', dataIndex: 'display_name' },
            { key: 'env', title: 'Environment', render: (_, s) => orDash(s.environment) },
            { key: 'address', title: 'Address', render: (_, s) => <AddressCell server={s} /> },
            { key: 'enabled', title: 'Status', render: (_, s) => <EnabledBadge enabled={s.enabled} /> },
            {
              key: 'hostids',
              title: 'Host identities',
              render: (_, s) =>
                s.active_host_identities === undefined
                  ? '—'
                  : s.active_host_identities === 0
                    ? 'None active'
                    : `${String(s.active_host_identities)} active`,
            },
            { key: 'groups', title: 'Groups', render: (_, s) => <TagList values={s.groups} /> },
            { key: 'labels', title: 'Labels', render: (_, s) => <TagList values={labelsToTags(s.labels)} /> },
          ]}
        />
      </Card>
      <FormModal<ServerFormValues>
        open={creating}
        title="New server"
        okText="Create server"
        formLabel="New server"
        initialValues={{ enabled: true, port: 22 }}
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          const server = await api.call('post', '/api/v1/servers', {
            body: toServerInput(values, { includeAddress: showAddress }),
            idempotencyKey,
          });
          await queryClient.invalidateQueries({ queryKey: qk.servers });
          setCreating(false);
          void navigate({ to: '/servers/$id', params: { id: server.id } });
        }}
      >
        <ServerFormFields mode="create" showAddress={showAddress} />
      </FormModal>
    </>
  );
}
