import { ArrowLeftOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Alert, Card, Space, Tag } from 'antd';

import { api } from '../../api/client';
import { operatorQueryOptions, operatorSessionsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Operator } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { formatDateTime } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { OperatorAccess } from './OperatorAccess';
import { OperatorChatLinks } from './OperatorChatLinks';
import { OperatorIdentities } from './OperatorIdentities';
import { roleLabel, shareableLink } from './roles';
import { WebSessionsTable } from './tables';
import { useOneTimeSecret } from './useOneTimeSecret';

function BackLink() {
  return (
    <Link to="/operators">
      <ArrowLeftOutlined aria-hidden="true" /> Operators
    </Link>
  );
}

function OperatorActions({ operator, isSelf }: { operator: Operator; isSelf: boolean }) {
  const queryClient = useQueryClient();
  const secret = useOneTimeSecret();
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.operator(operator.id) }),
      queryClient.invalidateQueries({ queryKey: qk.operators }),
    ]);

  return (
    <Space wrap>
      <ConfirmAction
        label="Issue reset link"
        title={`Issue a password reset link for ${operator.display_name}`}
        description="Creates a single-use link (valid 1 hour) that lets the operator choose a new password. Existing reset links are replaced. This is audited."
        confirmLabel="Issue link"
        danger={false}
        onConfirm={() =>
          api.call('post', '/api/v1/operators/{id}/reset-token', { path: { id: operator.id } })
        }
        onSuccess={(res) => {
          secret.show({
            title: 'Password reset link',
            label: 'Reset link',
            description: `Send this link to ${operator.display_name} over a trusted channel. It is single use and expires ${formatDateTime(res.expires_at)}.`,
            values: [shareableLink(res.url, res.token)],
          });
        }}
      />
      {operator.enabled ? (
        <ConfirmAction
          label="Disable"
          title={`Disable ${operator.display_name}`}
          description="The operator is signed out everywhere and cannot sign in or decide requests until re-enabled."
          typedConfirmation={operator.email ?? operator.display_name}
          confirmLabel="Disable operator"
          disabled={isSelf}
          buttonProps={isSelf ? { title: 'You cannot disable your own account' } : {}}
          onConfirm={() =>
            api.call('patch', '/api/v1/operators/{id}', {
              path: { id: operator.id },
              body: { enabled: false },
            })
          }
          onSuccess={() => {
            void refresh();
          }}
        />
      ) : (
        <ConfirmAction
          label="Enable"
          title={`Enable ${operator.display_name}`}
          description="The operator can sign in again with their existing credentials."
          confirmLabel="Enable operator"
          danger={false}
          onConfirm={() =>
            api.call('patch', '/api/v1/operators/{id}', {
              path: { id: operator.id },
              body: { enabled: true },
            })
          }
          onSuccess={() => {
            void refresh();
          }}
        />
      )}
      {secret.dialog}
    </Space>
  );
}

function OperatorSessions({ operator }: { operator: Operator }) {
  const sessions = useQuery(operatorSessionsQueryOptions(operator.id));
  const queryClient = useQueryClient();
  return (
    <Card
      title="Web sessions"
      size="small"
      extra={
        <ConfirmAction
          label="Sign out everywhere"
          title={`Sign out ${operator.display_name} everywhere`}
          description="Revokes every web session of this operator, including any you share with them. Live updates on those sessions stop immediately."
          confirmLabel="Revoke all sessions"
          buttonProps={{ size: 'small' }}
          disabled={(sessions.data?.items.length ?? 0) === 0}
          onConfirm={() =>
            api.call('delete', '/api/v1/operators/{id}/sessions', { path: { id: operator.id } })
          }
          onSuccess={() => {
            void queryClient.invalidateQueries({ queryKey: qk.operatorSessions(operator.id) });
          }}
        />
      }
    >
      <WebSessionsTable
        caption={`Web sessions of ${operator.display_name}`}
        rows={sessions.data?.items}
        loading={sessions.isPending}
        error={sessions.error}
        onRetry={() => void sessions.refetch()}
      />
    </Card>
  );
}

export function OperatorDetailPage({ id }: { id: string }) {
  const { can, me, loading: permsLoading } = usePermissions();
  const allowed = can('operators.manage');
  const operator = useQuery({ ...operatorQueryOptions(id), enabled: allowed });

  if (permsLoading) {
    return null;
  }
  if (!allowed) {
    return (
      <>
        <PageHeader title="Operator" above={<BackLink />} />
        <PermissionDenied />
      </>
    );
  }
  if (operator.isPending) {
    return (
      <>
        <PageHeader title="Operator" above={<BackLink />} />
        <LoadingState />
      </>
    );
  }
  if (operator.isError) {
    return (
      <>
        <PageHeader title="Operator" above={<BackLink />} />
        <ErrorState error={operator.error} onRetry={() => void operator.refetch()} />
      </>
    );
  }

  const op = operator.data;
  const isSelf = me?.operator.id === op.id;

  return (
    <>
      <PageHeader
        title={op.display_name}
        description={op.email}
        above={<BackLink />}
        extra={<OperatorActions operator={op} isSelf={isSelf} />}
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {isSelf ? (
          <Alert
            type="info"
            showIcon
            title="This is your account"
            description="You cannot disable your own account. Manage your password, two-factor and sessions on My account."
          />
        ) : null}
        <Card title="Profile" size="small">
          <KeyValueGrid
            items={[
              { span: 2, key: 'id', label: 'Operator ID', value: <code className="hp-mono">{op.id}</code> },
              {
                key: 'status',
                label: 'Status',
                value: op.enabled ? (
                  <StatusBadge tone="success">Enabled</StatusBadge>
                ) : (
                  <StatusBadge tone="neutral">Disabled</StatusBadge>
                ),
              },
              {
                key: 'roles',
                label: 'Effective roles',
                value: op.roles.length ? (
                  <Space size={4} wrap>
                    {op.roles.map((r) => (
                      <Tag key={r}>{roleLabel(r)}</Tag>
                    ))}
                  </Space>
                ) : (
                  'No roles'
                ),
              },
              { key: 'provisioned', label: 'Provisioned via', value: op.provisioned_via },
              { key: 'password', label: 'Local password', value: op.has_password ? 'Set' : 'Not set' },
              {
                key: 'mfa',
                label: 'Two-factor',
                value: `${op.mfa_enrolled ? 'Enrolled' : 'Not enrolled'}${op.mfa_required ? ' (required)' : ''}`,
              },
              { key: 'created', label: 'Created', value: formatDateTime(op.created_at) },
              { key: 'last', label: 'Last sign-in', value: formatDateTime(op.last_login_at) },
            ]}
          />
        </Card>
        <Card title="Roles and groups" size="small">
          <OperatorAccess operator={op} />
        </Card>
        <OperatorSessions operator={op} />
        <Card title="SSO identities" size="small">
          <OperatorIdentities operator={op} />
        </Card>
        <Card title="Chat accounts" size="small">
          <OperatorChatLinks operator={op} />
        </Card>
      </Space>
    </>
  );
}
