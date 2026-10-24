import { PlusOutlined, ScanOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Form, Input, Space, Table, Tag } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { hostIdentitiesQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { HostIdentity } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { Fingerprint } from '../../ds/Fingerprint';
import { EmptyState, ErrorState, LoadingState } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { OperatorName } from '../../shared/names';
import { StateBadge } from '../../shared/StateBadge';
import { FormModal } from './FormModal';

function ConfirmIdentity({ serverId, identity }: { serverId: string; identity: HostIdentity }) {
  const queryClient = useQueryClient();
  return (
    <ConfirmAction
      label="Confirm"
      danger={false}
      title="Confirm host identity"
      confirmLabel="Fingerprint matches, confirm"
      buttonProps={{ size: 'small', type: 'primary' }}
      description={
        <>
          <p>
            Compare this fingerprint with the destination&apos;s own key <strong>out of band</strong> (for
            example{' '}
            <code className="hp-mono">
              ssh-keygen -lf /etc/ssh/ssh_host_{identity.algorithm.replace(/^ssh-/, '')}_key.pub
            </code>{' '}
            on the host console). A scanned key is only as trustworthy as the network path it was read over.
          </p>
          <Fingerprint value={identity.fingerprint} />
        </>
      }
      onConfirm={() =>
        api.call('post', '/api/v1/host-identities/{id}/confirm', { path: { id: identity.id } })
      }
      onSuccess={() => {
        void queryClient.invalidateQueries({ queryKey: qk.hostIdentities(serverId) });
        void queryClient.invalidateQueries({ queryKey: qk.server(serverId) });
        void queryClient.invalidateQueries({ queryKey: qk.servers });
      }}
    />
  );
}

function RetireIdentity({ serverId, identity }: { serverId: string; identity: HostIdentity }) {
  const queryClient = useQueryClient();
  return (
    <ConfirmAction
      label="Retire"
      title="Retire host identity"
      confirmLabel="Retire"
      buttonProps={{ size: 'small' }}
      description={
        <>
          <p>
            The gateway will no longer accept this key from the destination. If it is the only active
            identity, connections to the server fail until another one is confirmed.
          </p>
          <Fingerprint value={identity.fingerprint} />
        </>
      }
      onConfirm={() => api.call('post', '/api/v1/host-identities/{id}/retire', { path: { id: identity.id } })}
      onSuccess={() => {
        void queryClient.invalidateQueries({ queryKey: qk.hostIdentities(serverId) });
        void queryClient.invalidateQueries({ queryKey: qk.server(serverId) });
        void queryClient.invalidateQueries({ queryKey: qk.servers });
      }}
    />
  );
}

/**
 * Destination host identities (PLAN §11.2, HP-SRV-004..007): enroll by pasting a known key or by scanning
 * and confirming the fingerprint out of band; retire old keys.
 */
/** A git host's published host key fingerprints, to compare scanned keys against. */
export interface PublishedHostKeys {
  name: string;
  fingerprints: string[];
  url: string;
}

export function HostIdentities({
  serverId,
  canWrite,
  published,
}: {
  serverId: string;
  canWrite: boolean;
  published?: PublishedHostKeys;
}) {
  const queryClient = useQueryClient();
  const query = useQuery(hostIdentitiesQueryOptions(serverId));
  const [adding, setAdding] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<unknown>(null);
  const [scanned, setScanned] = useState<HostIdentity[] | null>(null);

  const scan = async () => {
    setScanning(true);
    setScanError(null);
    try {
      const res = await api.call('post', '/api/v1/servers/{id}/host-identities:scan', {
        path: { id: serverId },
      });
      setScanned(res.items);
      await queryClient.invalidateQueries({ queryKey: qk.hostIdentities(serverId) });
    } catch (e) {
      setScanError(e);
    } finally {
      setScanning(false);
    }
  };

  return (
    <Card
      size="small"
      title="Host identities"
      extra={
        canWrite ? (
          <Space>
            <Button size="small" icon={<ScanOutlined />} loading={scanning} onClick={() => void scan()}>
              Scan host keys
            </Button>
            <Button
              size="small"
              icon={<PlusOutlined />}
              onClick={() => {
                setAdding(true);
              }}
            >
              Add key
            </Button>
          </Space>
        ) : null
      }
    >
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        {published ? (
          <p className="hp-legend" style={{ margin: 0 }}>
            Compare every fingerprint with the ones {published.name}{' '}
            <a href={published.url} target="_blank" rel="noreferrer">
              publishes
            </a>{' '}
            before confirming. Keys that match one of them exactly are marked.
          </p>
        ) : null}
        {scanError !== null ? (
          <Alert type="error" showIcon title="Scan failed" description={errorMessage(scanError)} />
        ) : null}
        {scanned !== null ? (
          <Alert
            type="warning"
            showIcon
            closable={{
              onClose: () => {
                setScanned(null);
              },
            }}
            title={`Scan returned ${String(scanned.length)} key${scanned.length === 1 ? '' : 's'} pending confirmation`}
            description="Scanned keys are not trusted until confirmed. Confirm only a fingerprint you verified on the host itself."
          />
        ) : null}
        {query.isPending ? (
          <LoadingState />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            title="No host identities"
            description="The gateway refuses to connect until a host key is confirmed. Scan or paste the destination's key."
          />
        ) : (
          <Table<HostIdentity>
            size="small"
            pagination={false}
            rowKey="id"
            dataSource={query.data.items}
            scroll={{ x: 'max-content' }}
            aria-label="Host identities"
            columns={[
              {
                key: 'fp',
                title: 'Fingerprint',
                render: (_, h) => (
                  <Space size={8} wrap>
                    <Fingerprint value={h.fingerprint} />
                    {published?.fingerprints.includes(h.fingerprint) ? (
                      <Tag color="green">Matches {published.name}&apos;s published key</Tag>
                    ) : null}
                  </Space>
                ),
              },
              { key: 'alg', title: 'Algorithm', dataIndex: 'algorithm' },
              {
                key: 'state',
                title: 'State',
                render: (_, h) => <StateBadge kind="hostIdentity" state={h.state} />,
              },
              { key: 'via', title: 'Enrolled via', dataIndex: 'enrolled_via' },
              {
                key: 'confirmed',
                title: 'Confirmed',
                render: (_, h) =>
                  h.confirmed_at ? (
                    <>
                      {formatDateTime(h.confirmed_at)}
                      {h.confirmed_by ? (
                        <>
                          {' '}
                          by <OperatorName id={h.confirmed_by} />
                        </>
                      ) : null}
                    </>
                  ) : (
                    '—'
                  ),
              },
              {
                key: 'actions',
                title: <span className="hp-visually-hidden">Actions</span>,
                render: (_, h) =>
                  canWrite ? (
                    <Space>
                      {h.state === 'pending' ? <ConfirmIdentity serverId={serverId} identity={h} /> : null}
                      {h.state !== 'retired' ? <RetireIdentity serverId={serverId} identity={h} /> : null}
                    </Space>
                  ) : null,
              },
            ]}
          />
        )}
      </Space>
      <FormModal<{ public_key: string }>
        open={adding}
        title="Add host key"
        okText="Add key"
        formLabel="Add host key"
        onCancel={() => {
          setAdding(false);
        }}
        onSubmit={async (values) => {
          await api.call('post', '/api/v1/servers/{id}/host-identities', {
            path: { id: serverId },
            body: { public_key: values.public_key.trim() },
          });
          await queryClient.invalidateQueries({ queryKey: qk.hostIdentities(serverId) });
          await queryClient.invalidateQueries({ queryKey: qk.server(serverId) });
          setAdding(false);
        }}
      >
        <Form.Item
          label="Host public key"
          name="public_key"
          rules={[{ required: true, message: 'Paste the host key' }]}
          extra="A known_hosts or .pub line taken from the host itself (e.g. /etc/ssh/ssh_host_ed25519_key.pub)."
        >
          <Input.TextArea rows={3} spellCheck={false} className="hp-mono" />
        </Form.Item>
      </FormModal>
    </Card>
  );
}
