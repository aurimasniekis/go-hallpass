import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Alert, Button, Card, Form, Input, InputNumber, Radio, Space } from 'antd';
import { useMemo, useState } from 'react';

import { api } from '../../api/client';
import { serversQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Server } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { usePermissions } from '../../lib/usePermissions';
import { EnabledBadge } from '../agents/AgentsPage';
import { FormModal } from '../servers/FormModal';
import { AddressCell } from '../servers/ServersPage';
import { GIT_HOST_PRESETS, presetFor } from './presets';

interface GitRemoteFormValues {
  preset: string;
  alias: string;
  description?: string;
  address: string;
  port: number;
}

const CUSTOM = 'custom';

function NewRemoteFields() {
  const form = Form.useFormInstance<GitRemoteFormValues>();
  return (
    <>
      <Form.Item label="Git host" name="preset">
        <Radio.Group
          optionType="button"
          options={[
            ...GIT_HOST_PRESETS.map((p) => ({ value: p.id, label: p.name })),
            { value: CUSTOM, label: 'Other host' },
          ]}
          onChange={(e) => {
            const p = GIT_HOST_PRESETS.find((x) => x.id === e.target.value);
            form.setFieldsValue(
              p ? { alias: p.alias, address: p.address, port: p.port } : { alias: '', address: '', port: 22 },
            );
          }}
        />
      </Form.Item>
      <Form.Item
        label="Name"
        name="alias"
        rules={[{ required: true, message: 'Enter a name' }]}
        extra={
          <>
            Agents use it as the first part of the repository path:{' '}
            <code className="hp-mono">git clone &lt;gateway&gt;:{'<name>'}/acme/api.git</code>
          </>
        }
      >
        <Input maxLength={63} />
      </Form.Item>
      <Form.Item label="Description" name="description">
        <Input maxLength={200} />
      </Form.Item>
      <Space size={12} align="start" wrap>
        <Form.Item label="Host" name="address" rules={[{ required: true, message: 'Enter the git host' }]}>
          <Input style={{ width: 280 }} spellCheck={false} />
        </Form.Item>
        <Form.Item label="SSH port" name="port" rules={[{ required: true }]}>
          <InputNumber min={1} max={65535} />
        </Form.Item>
      </Space>
    </>
  );
}

/** Git remotes: git hosts agents reach with plain git through the gateway (separate from SSH servers). */
export function GitRemotesPage() {
  const { can, loading } = usePermissions();
  const query = useQuery({ ...serversQueryOptions(), enabled: can('inventory.read') });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const rows = useMemo(() => query.data?.items.filter((s) => s.kind === 'git'), [query.data]);

  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Git" />
        <PermissionDenied />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Git"
        description="Git hosts agents reach with plain git through the gateway, with approval, repository patterns and push rules."
        extra={
          can('inventory.write') ? (
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                setCreating(true);
              }}
            >
              New git remote
            </Button>
          ) : null
        }
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Alert
          type="info"
          showIcon
          title="How agents use it"
          description={
            <>
              Agents keep their usual <code className="hp-mono">Host</code> entry for the gateway and use
              plain git: <code className="hp-mono">git clone center:github/acme/api.git</code>,{' '}
              <code className="hp-mono">git push</code>. The gateway only connects to hosts inside{' '}
              <code className="hp-mono">egress.allow_cidrs</code>, so add the git host&apos;s address ranges
              there.
            </>
          }
        />
        <Card size="small">
          <DataTable<Server>
            caption="Git remotes"
            rowKey="id"
            rows={rows}
            loading={query.isPending}
            fetching={query.isFetching}
            error={query.error}
            onRetry={() => void query.refetch()}
            emptyTitle="No git remotes"
            emptyDescription="Add GitHub, GitLab, Bitbucket or your own git host."
            columns={[
              {
                key: 'alias',
                title: 'Name',
                render: (_, s) => (
                  <Link to="/git/$id" params={{ id: s.id }}>
                    {s.alias}
                  </Link>
                ),
              },
              { key: 'host', title: 'Host', render: (_, s) => presetFor(s.address)?.name ?? 'Other host' },
              { key: 'address', title: 'Address', render: (_, s) => <AddressCell server={s} /> },
              {
                key: 'identities',
                title: 'Host keys',
                render: (_, s) => ((s.active_host_identities ?? 0) > 0 ? 'Pinned' : 'Not confirmed'),
              },
              { key: 'enabled', title: 'Status', render: (_, s) => <EnabledBadge enabled={s.enabled} /> },
            ]}
          />
        </Card>
      </Space>
      <FormModal<GitRemoteFormValues>
        open={creating}
        title="New git remote"
        okText="Create git remote"
        formLabel="New git remote"
        width={640}
        initialValues={{
          preset: GIT_HOST_PRESETS[0]?.id ?? CUSTOM,
          alias: GIT_HOST_PRESETS[0]?.alias ?? '',
          address: GIT_HOST_PRESETS[0]?.address ?? '',
          port: 22,
        }}
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          const created = await api.call('post', '/api/v1/servers', {
            body: {
              kind: 'git',
              alias: values.alias.trim(),
              description: (values.description ?? '').trim(),
              address: values.address.trim(),
              port: values.port,
            },
            idempotencyKey,
          });
          await queryClient.invalidateQueries({ queryKey: qk.servers });
          setCreating(false);
          await navigate({ to: '/git/$id', params: { id: created.id } });
        }}
      >
        <NewRemoteFields />
      </FormModal>
    </>
  );
}
