import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Card, Form, Input, Table } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { userCAsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { UserCA } from '../../api/types';
import { CopyField } from '../../ds/CopyField';
import { Fingerprint } from '../../ds/Fingerprint';
import { EmptyState, ErrorState, LoadingState } from '../../ds/states';
import { StateBadge } from '../../shared/StateBadge';
import { FormModal } from '../servers/FormModal';

/**
 * User certificate authorities (PLAN §11.3): Hallpass can log in to destinations with short-lived
 * certificates signed by one of these CAs. Destinations trust the CA via `TrustedUserCAKeys`.
 */
export function UserCAsPanel() {
  const queryClient = useQueryClient();
  const query = useQuery(userCAsQueryOptions());
  const [creating, setCreating] = useState(false);
  const [shown, setShown] = useState<string | null>(null);
  const items = query.data?.items ?? [];
  const showCA = items.find((c) => c.id === shown);
  return (
    <Card
      size="small"
      title="User certificate authorities"
      extra={
        <Button
          size="small"
          icon={<PlusOutlined />}
          onClick={() => {
            setCreating(true);
          }}
        >
          New CA
        </Button>
      }
    >
      {query.isPending ? (
        <LoadingState />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState
          title="No user CAs"
          description="Create one to use certificate logins instead of static keys."
        />
      ) : (
        <>
          <Table<UserCA>
            size="small"
            pagination={false}
            rowKey="id"
            dataSource={items}
            scroll={{ x: 'max-content' }}
            aria-label="User certificate authorities"
            columns={[
              { key: 'name', title: 'Name', dataIndex: 'name' },
              { key: 'fp', title: 'Fingerprint', render: (_, c) => <Fingerprint value={c.fingerprint} /> },
              { key: 'alg', title: 'Algorithm', dataIndex: 'algorithm' },
              { key: 'ext', title: 'Source', render: (_, c) => (c.external ? 'External' : 'Hallpass') },
              {
                key: 'state',
                title: 'State',
                render: (_, c) => <StateBadge kind="generic" state={c.state} />,
              },
              {
                key: 'pub',
                title: <span className="hp-visually-hidden">Public key</span>,
                render: (_, c) => (
                  <Button
                    size="small"
                    type="link"
                    onClick={() => {
                      setShown(c.id);
                    }}
                  >
                    Public key
                  </Button>
                ),
              },
            ]}
          />
          {showCA ? (
            <div style={{ marginTop: 12 }}>
              <CopyField label={`${showCA.name} public key (TrustedUserCAKeys)`} value={showCA.public_key} />
            </div>
          ) : null}
        </>
      )}
      <FormModal<{ name: string }>
        open={creating}
        title="New user CA"
        okText="Create CA"
        formLabel="New user CA"
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (v) => {
          const ca = await api.call('post', '/api/v1/user-cas', { body: { name: v.name.trim() } });
          await queryClient.invalidateQueries({ queryKey: qk.userCAs });
          setShown(ca.id);
          setCreating(false);
        }}
      >
        <Form.Item label="Name" name="name" rules={[{ required: true, message: 'Enter a name' }]}>
          <Input maxLength={128} />
        </Form.Item>
      </FormModal>
    </Card>
  );
}
