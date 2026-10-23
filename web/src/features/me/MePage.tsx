import { useQuery } from '@tanstack/react-query';
import { Card, Space, Tag } from 'antd';

import { meQueryOptions } from '../../api/queries';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { roleLabel } from '../operators/roles';
import { ChatAccounts } from './ChatAccounts';
import { MyIdentities, MySessions, PasswordChange, TwoFactor } from './SecurityCards';

const METHOD_LABEL: Record<string, string> = {
  password: 'Password',
  oidc: 'Single sign-on',
  breakglass: 'Break-glass recovery',
};

/** My account: profile, sessions, password, two-factor, SSO identities and chat accounts. */
export function MePage() {
  const me = useQuery(meQueryOptions());

  if (me.isPending) {
    return (
      <>
        <PageHeader title="My account" />
        <LoadingState />
      </>
    );
  }
  if (me.isError) {
    return (
      <>
        <PageHeader title="My account" />
        <ErrorState error={me.error} onRetry={() => void me.refetch()} />
      </>
    );
  }

  const { operator, session, permissions } = me.data;
  return (
    <>
      <PageHeader title="My account" description={operator.email} />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card title="Profile" size="small">
          <KeyValueGrid
            items={[
              { key: 'name', label: 'Display name', value: operator.display_name },
              { key: 'email', label: 'Email', value: operator.email ?? '—' },
              {
                key: 'roles',
                label: 'Roles',
                value: operator.roles.length ? (
                  <Space size={4} wrap>
                    {operator.roles.map((r) => (
                      <Tag key={r}>{roleLabel(r)}</Tag>
                    ))}
                  </Space>
                ) : (
                  'No roles'
                ),
              },
              { key: 'perms', label: 'Permissions', value: `${String(permissions.length)} granted` },
              {
                span: 2,
                key: 'id',
                label: 'Operator ID',
                value: <code className="hp-mono">{operator.id}</code>,
              },
              {
                key: 'method',
                label: 'Signed in with',
                value: METHOD_LABEL[session.method] ?? session.method,
              },
              { key: 'auth', label: 'Signed in at', value: formatDateTime(session.auth_at) },
              { key: 'mfa', label: 'Last two-factor check', value: formatDateTime(session.mfa_at) },
              { key: 'expires', label: 'Session expires', value: formatDateTime(session.expires_at) },
            ]}
          />
        </Card>
        <Card title="Sessions" size="small">
          <MySessions />
        </Card>
        {operator.has_password ? (
          <Card title="Password" size="small">
            <PasswordChange />
          </Card>
        ) : null}
        <Card title="Two-factor authentication" size="small">
          <TwoFactor me={me.data} />
        </Card>
        <Card title="SSO identities" size="small">
          <MyIdentities me={me.data} />
        </Card>
        <Card title="Chat accounts" size="small">
          <ChatAccounts />
        </Card>
      </Space>
    </>
  );
}
