import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Form, Input, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { qk } from '../../api/queryKeys';
import type { HostCA, Server } from '../../api/types';
import { DurationInput } from '../../ds/DurationInput';
import { Fingerprint } from '../../ds/Fingerprint';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { TagsInput } from '../../ds/TagsInput';
import { formatDuration } from '../../lib/format';
import { FormModal } from './FormModal';
import { cleanList } from './formUtils';
import { HostCASetupTip } from './SetupTips';

/**
 * Host certificate authority for a server (PLAN §11.2): trust host certificates signed by a CA instead of
 * pinning individual keys. The API has no host-CA list endpoint, so a newly created CA's ID is shown once
 * here and binding takes a CA ID.
 */
export function HostCAPanel({ server, canWrite }: { server: Server; canWrite: boolean }) {
  const queryClient = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [binding, setBinding] = useState(false);
  const [created, setCreated] = useState<HostCA | null>(null);
  return (
    <Card
      size="small"
      title="Host certificate authority"
      extra={
        canWrite ? (
          <Space>
            <Button
              size="small"
              onClick={() => {
                setCreating(true);
              }}
            >
              Register CA
            </Button>
            <Button
              size="small"
              onClick={() => {
                setBinding(true);
              }}
            >
              Bind CA
            </Button>
          </Space>
        ) : null
      }
    >
      <Space orientation="vertical" style={{ width: '100%' }}>
        <KeyValueGrid
          items={[
            {
              key: 'ca',
              label: 'Bound CA',
              value: server.host_ca_id ? (
                <code className="hp-mono">{server.host_ca_id}</code>
              ) : (
                'None (key pinning)'
              ),
            },
            {
              key: 'principals',
              label: 'Accepted principals',
              value: server.host_ca_principals?.length ? server.host_ca_principals.join(', ') : '—',
            },
          ]}
        />
        {created ? (
          <Alert
            type="success"
            showIcon
            closable={{
              onClose: () => {
                setCreated(null);
              },
            }}
            title={`Registered host CA "${created.name}"`}
            description={
              <>
                <div>
                  ID <code className="hp-mono">{created.id}</code> — use it to bind servers. Max validity{' '}
                  {formatDuration(created.max_validity)}.
                </div>
                <Fingerprint value={created.fingerprint} />
              </>
            }
          />
        ) : null}
      </Space>
      <FormModal<{ name: string; public_key: string; max_validity?: number | null }>
        open={creating}
        title="Register host CA"
        width={720}
        okText="Register"
        formLabel="Register host CA"
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (v) => {
          const ca = await api.call('post', '/api/v1/host-cas', {
            body: {
              name: v.name.trim(),
              public_key: v.public_key.trim(),
              ...(v.max_validity ? { max_validity: v.max_validity } : {}),
            },
          });
          setCreated(ca);
          setCreating(false);
        }}
      >
        <HostCASetupTip
          alias={server.alias}
          principals={[server.alias, ...(server.address && !server.address_redacted ? [server.address] : [])]}
        />
        <Form.Item label="Name" name="name" rules={[{ required: true, message: 'Enter a name' }]}>
          <Input maxLength={128} />
        </Form.Item>
        <Form.Item
          label="CA public key"
          name="public_key"
          rules={[{ required: true, message: 'Paste the CA public key' }]}
        >
          <Input.TextArea
            rows={3}
            spellCheck={false}
            className="hp-mono"
            placeholder="ssh-ed25519 AAAA… hallpass-host-ca"
          />
        </Form.Item>
        <Form.Item label="Maximum certificate validity" name="max_validity" extra="Optional.">
          <DurationInput aria-label="Maximum certificate validity" minSeconds={60} />
        </Form.Item>
      </FormModal>
      <FormModal<{ host_ca_id: string; principals?: string[] }>
        open={binding}
        title="Bind host CA"
        okText="Bind"
        formLabel="Bind host CA"
        initialValues={{
          host_ca_id: created?.id ?? server.host_ca_id ?? '',
          principals: server.host_ca_principals ?? [],
        }}
        onCancel={() => {
          setBinding(false);
        }}
        onSubmit={async (v) => {
          await api.call('put', '/api/v1/servers/{id}/host-ca-binding', {
            path: { id: server.id },
            body: { host_ca_id: v.host_ca_id.trim(), principals: cleanList(v.principals) },
          });
          await queryClient.invalidateQueries({ queryKey: qk.server(server.id) });
          setBinding(false);
        }}
      >
        <Form.Item
          label="Host CA ID"
          name="host_ca_id"
          rules={[{ required: true, message: 'Enter the CA ID' }]}
        >
          <Input spellCheck={false} className="hp-mono" />
        </Form.Item>
        <Form.Item
          label="Principals"
          name="principals"
          rules={[{ required: true, message: 'Add at least one principal' }]}
          extra="Host names the certificate must name (e.g. db1.internal)."
        >
          <TagsInput aria-label="Principals" />
        </Form.Item>
      </FormModal>
    </Card>
  );
}
