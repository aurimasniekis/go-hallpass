import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Alert, Button, Card, Form, Input, Radio, Space } from 'antd';
import { useMemo, useState } from 'react';

import { api } from '../../api/client';
import { serversQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Server } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { TagsInput } from '../../ds/TagsInput';
import { usePermissions } from '../../lib/usePermissions';
import { EnabledBadge } from '../agents/AgentsPage';
import { FormModal } from '../servers/FormModal';
import { API_PRESETS, CUSTOM_PRESET, presetForHosts } from './presets';

interface ApiTargetFormValues {
  preset: string;
  alias: string;
  description?: string;
  hosts: string[];
}

/** Host fields shared by the create and edit dialogs. */
export function ApiHostsField() {
  return (
    <Form.Item
      label="Hosts"
      name="hosts"
      rules={[{ required: true, type: 'array', min: 1, message: 'Add at least one host' }]}
      extra={
        <>
          HTTPS host names agents call, e.g. <code className="hp-mono">api.github.com</code> or{' '}
          <code className="hp-mono">*.googleapis.com</code> (every subdomain). No IP addresses; port 443 only.
          Changing them issues a new CA that agents must fetch again.
        </>
      }
    >
      <TagsInput aria-label="Hosts" tokenSeparators={[' ', ',', '\n']} placeholder="api.example.com" />
    </Form.Item>
  );
}

function NewTargetFields() {
  const form = Form.useFormInstance<ApiTargetFormValues>();
  return (
    <>
      <Form.Item label="API" name="preset">
        <Radio.Group
          optionType="button"
          options={[...API_PRESETS, CUSTOM_PRESET].map((p) => ({ value: p.id, label: p.name }))}
          onChange={(e) => {
            const p = API_PRESETS.find((x) => x.id === e.target.value) ?? CUSTOM_PRESET;
            form.setFieldsValue({ alias: p.alias, hosts: p.hosts });
          }}
        />
      </Form.Item>
      <Form.Item
        label="Name"
        name="alias"
        rules={[{ required: true, message: 'Enter a name' }]}
        extra="Agents request access with it: ssh <gateway> request <name> --role <profile> …"
      >
        <Input maxLength={63} />
      </Form.Item>
      <Form.Item label="Description" name="description">
        <Input maxLength={200} />
      </Form.Item>
      <ApiHostsField />
    </>
  );
}

/** API targets: HTTPS APIs agents call through the gateway's API proxy, which adds the credential. */
export function ApiTargetsPage() {
  const { can, loading } = usePermissions();
  const query = useQuery({ ...serversQueryOptions(), enabled: can('inventory.read') });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [creating, setCreating] = useState(false);
  const rows = useMemo(() => query.data?.items.filter((s) => s.kind === 'api'), [query.data]);
  const first = API_PRESETS[0] ?? CUSTOM_PRESET;

  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="APIs" />
        <PermissionDenied />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="APIs"
        description="HTTPS APIs agents call with their usual tools through the gateway's API proxy, which adds your credential: agents never hold it."
        extra={
          can('inventory.write') ? (
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                setCreating(true);
              }}
            >
              New API target
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
              Agents open a tunnel with{' '}
              <code className="hp-mono">ssh -fN -o ClearAllForwardings=no -L 127.0.0.1:18080:hallpass:443 center</code>, load the proxy
              settings with <code className="hp-mono">eval &quot;$(ssh center api env)&quot;</code> and then
              run <code className="hp-mono">gh</code>, <code className="hp-mono">wrangler</code>,{' '}
              <code className="hp-mono">gcloud</code> or <code className="hp-mono">curl</code> as usual. Every
              request is checked against the profile&apos;s rules and recorded.
            </>
          }
        />
        <Card size="small">
          <DataTable<Server>
            caption="API targets"
            rowKey="id"
            rows={rows}
            loading={query.isPending}
            fetching={query.isFetching}
            error={query.error}
            onRetry={() => void query.refetch()}
            emptyTitle="No API targets"
            emptyDescription="Add GitHub, Cloudflare, Google Cloud or any HTTPS API."
            columns={[
              {
                key: 'alias',
                title: 'Name',
                render: (_, s) => (
                  <Link to="/apis/$id" params={{ id: s.id }}>
                    {s.alias}
                  </Link>
                ),
              },
              {
                key: 'api',
                title: 'API',
                render: (_, s) => presetForHosts(s.api?.hosts)?.name ?? CUSTOM_PRESET.name,
              },
              {
                key: 'hosts',
                title: 'Hosts',
                render: (_, s) => (
                  <Space size={4} wrap>
                    {(s.api?.hosts ?? []).map((h) => (
                      <code key={h} className="hp-mono">
                        {h}
                      </code>
                    ))}
                  </Space>
                ),
              },
              { key: 'enabled', title: 'Status', render: (_, s) => <EnabledBadge enabled={s.enabled} /> },
            ]}
          />
        </Card>
      </Space>
      <FormModal<ApiTargetFormValues>
        open={creating}
        title="New API target"
        okText="Create API target"
        formLabel="New API target"
        width={640}
        initialValues={{ preset: first.id, alias: first.alias, hosts: first.hosts }}
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          const created = await api.call('post', '/api/v1/servers', {
            body: {
              kind: 'api',
              alias: values.alias.trim(),
              description: (values.description ?? '').trim(),
              api: { hosts: values.hosts.map((h) => h.trim().toLowerCase()) },
            },
            idempotencyKey,
          });
          await queryClient.invalidateQueries({ queryKey: qk.servers });
          setCreating(false);
          await navigate({ to: '/apis/$id', params: { id: created.id } });
        }}
      >
        <NewTargetFields />
      </FormModal>
    </>
  );
}
