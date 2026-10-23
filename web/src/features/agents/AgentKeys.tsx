import { PlusOutlined } from '@ant-design/icons';
import { useQueryClient } from '@tanstack/react-query';
import { Button, Card, Form, Input, Table } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { qk } from '../../api/queryKeys';
import type { AgentKey } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { Fingerprint } from '../../ds/Fingerprint';
import { EmptyState } from '../../ds/states';
import { UntrustedText } from '../../ds/UntrustedText';
import { formatDateTime } from '../../lib/format';
import { StateBadge } from '../../shared/StateBadge';
import { FormModal } from '../servers/FormModal';

function RevokeKey({ agentId, keyItem }: { agentId: string; keyItem: AgentKey }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState('');
  return (
    <ConfirmAction
      label="Revoke"
      title="Revoke agent key"
      confirmLabel="Revoke key"
      buttonProps={{ size: 'small' }}
      onOpen={() => {
        setReason('');
      }}
      description={
        <>
          <p>
            The agent can no longer authenticate with <code className="hp-mono">{keyItem.fingerprint}</code>.
            Open connections using it are not affected by this alone.
          </p>
          <label htmlFor={`revoke-reason-${keyItem.id}`}>Reason (recorded in the audit log)</label>
          <Input
            id={`revoke-reason-${keyItem.id}`}
            value={reason}
            maxLength={1000}
            onChange={(e) => {
              setReason(e.target.value);
            }}
          />
        </>
      }
      onConfirm={({ idempotencyKey }) =>
        api.call('post', '/api/v1/agents/{id}/keys/{kid}/revoke', {
          path: { id: agentId, kid: keyItem.id },
          body: reason.trim() ? { reason: reason.trim() } : {},
          idempotencyKey,
        })
      }
      onSuccess={() => void queryClient.invalidateQueries({ queryKey: qk.agent(agentId) })}
    />
  );
}

/** Agent SSH keys (HP-AGT-*): add an authorized_keys line, revoke a key. */
export function AgentKeys({
  agentId,
  keys,
  canWrite,
}: {
  agentId: string;
  keys: readonly AgentKey[];
  canWrite: boolean;
}) {
  const queryClient = useQueryClient();
  const [adding, setAdding] = useState(false);
  return (
    <Card
      size="small"
      title="SSH keys"
      extra={
        canWrite ? (
          <Button
            size="small"
            icon={<PlusOutlined />}
            onClick={() => {
              setAdding(true);
            }}
          >
            Add key
          </Button>
        ) : null
      }
    >
      {keys.length === 0 ? (
        <EmptyState title="No keys" description="The agent cannot connect until a public key is added." />
      ) : (
        <Table<AgentKey>
          size="small"
          pagination={false}
          rowKey="id"
          dataSource={keys}
          scroll={{ x: 'max-content' }}
          aria-label="Agent SSH keys"
          columns={[
            {
              key: 'fp',
              title: 'Fingerprint',
              // Long fingerprints wrap instead of pushing the other columns out of the card.
              onCell: () => ({ style: { minWidth: 240, maxWidth: 340 } }),
              render: (_, k) => <Fingerprint value={k.fingerprint} />,
            },
            {
              key: 'alg',
              title: 'Algorithm',
              render: (_, k) => `${k.algorithm}${k.bits ? ` (${String(k.bits)} bits)` : ''}`,
            },
            {
              key: 'comment',
              title: 'Comment',
              render: (_, k) => <UntrustedText text={k.comment} source="the public key" maxLength={80} />,
            },
            { key: 'state', title: 'State', render: (_, k) => <StateBadge kind="generic" state={k.state} /> },
            { key: 'created', title: 'Added', render: (_, k) => formatDateTime(k.created_at) },
            { key: 'used', title: 'Last used', render: (_, k) => formatDateTime(k.last_used_at ?? null) },
            {
              key: 'actions',
              title: <span className="hp-visually-hidden">Actions</span>,
              fixed: 'right',
              render: (_, k) =>
                canWrite && k.state === 'active' ? <RevokeKey agentId={agentId} keyItem={k} /> : null,
            },
          ]}
        />
      )}
      <FormModal<{ public_key: string }>
        open={adding}
        title="Add public key"
        okText="Add key"
        formLabel="Add public key"
        onCancel={() => {
          setAdding(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          await api.call('post', '/api/v1/agents/{id}/keys', {
            path: { id: agentId },
            body: { public_key: values.public_key.trim() },
            idempotencyKey,
          });
          await queryClient.invalidateQueries({ queryKey: qk.agent(agentId) });
          setAdding(false);
        }}
      >
        <Form.Item
          label="Public key"
          name="public_key"
          rules={[{ required: true, message: 'Paste the authorized_keys line' }]}
          extra="One authorized_keys line, e.g. ssh-ed25519 AAAA… agent@host. Never paste a private key."
        >
          <Input.TextArea rows={3} spellCheck={false} className="hp-mono" />
        </Form.Item>
      </FormModal>
    </Card>
  );
}
