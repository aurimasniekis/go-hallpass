import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Form, Input, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { destinationCollectorsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { DestinationCollector } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { Fingerprint } from '../../ds/Fingerprint';
import { EmptyState, ErrorState, LoadingState } from '../../ds/states';
import { revealControls } from '../../ds/untrusted';
import { formatDateTime } from '../../lib/format';
import { OperatorName } from '../../shared/names';
import { StateBadge } from '../../shared/StateBadge';
import { FormModal } from './FormModal';
import { ResponsiveTable } from '../../ds/DataTable';

function RevokeCollector({ collector, serverId }: { collector: DestinationCollector; serverId: string }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState('');
  return (
    <ConfirmAction
      label="Revoke"
      title="Revoke destination collector"
      confirmLabel="Revoke collector"
      buttonProps={{ size: 'small' }}
      onOpen={() => {
        setReason('');
      }}
      description={
        <>
          <p>HallPass stops accepting reports signed by this collector key.</p>
          <Fingerprint value={collector.fingerprint} />
          <label htmlFor={`collector-revoke-${collector.id}`} style={{ display: 'block', marginTop: 8 }}>
            Reason (recorded in the audit log)
          </label>
          <Input
            id={`collector-revoke-${collector.id}`}
            value={reason}
            maxLength={1000}
            onChange={(e) => {
              setReason(e.target.value);
            }}
          />
        </>
      }
      onConfirm={({ idempotencyKey }) =>
        api.call('post', '/api/v1/destination-collectors/{id}/revoke', {
          path: { id: collector.id },
          body: reason.trim() ? { reason: reason.trim() } : {},
          idempotencyKey,
        })
      }
      onSuccess={() => {
        void queryClient.invalidateQueries({ queryKey: qk.serverDestinationCollectors(serverId) });
        void queryClient.invalidateQueries({ queryKey: qk.destinationCollectors });
      }}
    />
  );
}

/**
 * Destination audit collectors (WP25): agents running on the destination that report process activity to
 * HallPass. Their reports are destination-reported and never verified by HallPass (HP-REC-006).
 */
export function DestinationCollectors({ serverId, canManage }: { serverId: string; canManage: boolean }) {
  const queryClient = useQueryClient();
  const query = useQuery(destinationCollectorsQueryOptions(serverId));
  const [registering, setRegistering] = useState(false);
  return (
    <Card
      size="small"
      title="Destination audit collectors"
      extra={
        canManage ? (
          <Button
            size="small"
            icon={<PlusOutlined />}
            onClick={() => {
              setRegistering(true);
            }}
          >
            Register collector
          </Button>
        ) : null
      }
    >
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <Alert
          type="info"
          showIcon
          title="Destination-reported, not verified"
          description="Collector reports come from software on the destination. A compromised destination can omit or forge them, so HallPass shows them as destination-reported and never as verified."
        />
        {query.isPending ? (
          <LoadingState />
        ) : query.isError ? (
          <ErrorState
            error={query.error}
            onRetry={() => {
              void query.refetch();
            }}
          />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            title="No collectors"
            description="Register a collector's public key to accept its reports."
          />
        ) : (
          <ResponsiveTable<DestinationCollector>
            size="small"
            pagination={false}
            rowKey="id"
            dataSource={query.data.items}
            scroll={{ x: 'max-content' }}
            aria-label="Destination audit collectors"
            columns={[
              { key: 'name', title: 'Name', dataIndex: 'name' },
              { key: 'fp', title: 'Fingerprint', render: (_, c) => <Fingerprint value={c.fingerprint} /> },
              {
                key: 'state',
                title: 'State',
                render: (_, c) => <StateBadge kind="generic" state={c.state} />,
              },
              { key: 'seq', title: 'Last sequence', dataIndex: 'last_seq' },
              { key: 'seen', title: 'Last seen', render: (_, c) => formatDateTime(c.last_seen_at ?? null) },
              {
                key: 'created',
                title: 'Registered',
                render: (_, c) => (
                  <>
                    {formatDateTime(c.created_at)} by <OperatorName id={c.created_by} />
                  </>
                ),
              },
              {
                key: 'revoked',
                title: 'Revoked',
                render: (_, c) =>
                  c.revoked_at ? (
                    <>
                      {formatDateTime(c.revoked_at)}
                      {c.revoked_by ? (
                        <>
                          {' '}
                          by <OperatorName id={c.revoked_by} />
                        </>
                      ) : null}
                      {c.revoke_reason ? <div>{revealControls(c.revoke_reason)}</div> : null}
                    </>
                  ) : (
                    '—'
                  ),
              },
              {
                key: 'actions',
                title: <span className="hp-visually-hidden">Actions</span>,
                render: (_, c) =>
                  canManage && c.state === 'active' ? (
                    <RevokeCollector collector={c} serverId={serverId} />
                  ) : null,
              },
            ]}
          />
        )}
      </Space>
      <FormModal<{ name: string; public_key: string }>
        open={registering}
        title="Register destination collector"
        okText="Register"
        formLabel="Register destination collector"
        onCancel={() => {
          setRegistering(false);
        }}
        onSubmit={async (v) => {
          await api.call('post', '/api/v1/destination-collectors', {
            body: { server_id: serverId, name: v.name.trim(), public_key: v.public_key.trim() },
          });
          await queryClient.invalidateQueries({ queryKey: qk.serverDestinationCollectors(serverId) });
          await queryClient.invalidateQueries({ queryKey: qk.destinationCollectors });
          setRegistering(false);
        }}
      >
        <Form.Item label="Name" name="name" rules={[{ required: true, message: 'Enter a name' }]}>
          <Input maxLength={128} />
        </Form.Item>
        <Form.Item
          label="Collector public key"
          name="public_key"
          rules={[{ required: true, message: 'Paste the collector key' }]}
          extra={
            <>
              The ssh-ed25519 authorized_keys line printed by{' '}
              <code className="hp-mono">hallpass-collector pubkey</code> on the destination.
            </>
          }
        >
          <Input.TextArea rows={3} spellCheck={false} className="hp-mono" />
        </Form.Item>
      </FormModal>
    </Card>
  );
}
