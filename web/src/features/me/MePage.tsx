import { useQuery } from '@tanstack/react-query';
import { Card, Space } from 'antd';

import { meQueryOptions } from '../../api/queries';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, NotImplemented } from '../../ds/states';

function when(value: string | undefined): string {
  if (!value) {
    return '—';
  }
  const t = Date.parse(value);
  return Number.isNaN(t) ? value : new Date(t).toLocaleString();
}

export function MePage() {
  const me = useQuery(meQueryOptions());
  return (
    <>
      <PageHeader title="My account" />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card title="Profile" size="small">
          {me.isPending ? (
            <LoadingState />
          ) : me.isError ? (
            <ErrorState
              error={me.error}
              onRetry={() => {
                void me.refetch();
              }}
            />
          ) : (
            <KeyValueGrid
              items={[
                { key: 'name', label: 'Display name', value: me.data.display_name },
                {
                  key: 'id',
                  label: 'Operator ID',
                  value: <code className="hp-mono">{me.data.operator_id}</code>,
                },
                {
                  key: 'roles',
                  label: 'Roles',
                  value: me.data.roles.length ? me.data.roles.join(', ') : '—',
                },
                { key: 'auth', label: 'Signed in', value: when(me.data.auth_time) },
                { key: 'mfa', label: 'Last MFA verification', value: when(me.data.mfa_at) },
              ]}
            />
          )}
        </Card>
        <Card title="Security" size="small">
          <NotImplemented feature="Password, MFA, recovery codes and session management" workPackage="WP20" />
        </Card>
      </Space>
    </>
  );
}
