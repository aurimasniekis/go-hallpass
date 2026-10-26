import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Form, Input, InputNumber, Select, Switch } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { qk } from '../../api/queryKeys';
import type { APIToken, OperatorRole } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { formatDateTime } from '../../lib/format';
import { useNow } from '../../lib/useNow';
import { usePermissions } from '../../lib/usePermissions';
import { OperatorName } from '../../shared/names';
import { OPERATOR_ROLES, roleLabel } from '../operators/roles';
import { useOneTimeSecret } from '../operators/useOneTimeSecret';
import { FormModal } from '../servers/FormModal';

interface TokenFormValues {
  name: string;
  role: OperatorRole;
  expires_in_days?: number;
  never_expires?: boolean;
}

function TokenState({ token, now }: { token: APIToken; now: number }) {
  if (token.revoked_at) {
    return <StatusBadge tone="neutral">Revoked</StatusBadge>;
  }
  if (token.expires_at && new Date(token.expires_at).getTime() <= now) {
    return <StatusBadge tone="warning">Expired</StatusBadge>;
  }
  return <StatusBadge tone="success">Active</StatusBadge>;
}

/**
 * Automation tokens for Terraform and scripts (ADR-0052, ADR-0058). A token acts for the operator who created it with
 * one of their roles (any role for an administrator), only on configuration and read operations; it is shown once and
 * stored only as a keyed hash. Tokens issued by an administrator token are listed with their parent.
 */
export function ApiTokensPage() {
  const { can, me, loading } = usePermissions();
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const secret = useOneTimeSecret();
  const [creating, setCreating] = useState(false);
  const now = useNow(60_000);
  const tokens = useQuery({
    queryKey: qk.apiTokens,
    queryFn: async () => (await api.call('get', '/api/v1/api-tokens')).items,
    enabled: can('operators.manage'),
  });
  if (!loading && !can('operators.manage')) {
    return (
      <>
        <PageHeader title="API tokens" />
        <PermissionDenied />
      </>
    );
  }
  const myRoles: OperatorRole[] = me?.operator.roles ?? [];
  const isAdmin = myRoles.includes('administrator');
  const roleChoices = isAdmin ? OPERATOR_ROLES.map((r) => r.value) : myRoles;
  const tokenName = (id: string) => tokens.data?.find((t) => t.id === id)?.name ?? id;
  return (
    <>
      <PageHeader
        title="API tokens"
        description="Tokens for Terraform and scripts that manage HallPass through its API."
        extra={
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setCreating(true);
            }}
          >
            New token
          </Button>
        }
      />
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="What a token can do"
        description={
          <>
            A token acts for you with one role until it expires or is revoked, or for good if you choose
            &quot;Never expires&quot;. Administrators may pick any role, for example Auditor for a read-only
            integration; other operators pick one of their own. It stops working if your account is disabled
            or you lose that role (and are not an administrator). It can read what the role allows and change
            configuration: agents, servers, git remotes, roles, keys, policy, single sign-on, chat
            integrations and, with the Administrator role, operators and the tokens it issues itself. It can
            never approve or deny requests, revoke access, read recordings, invite operators or use lockdown.
            Its changes are recorded in the audit log under your name, marked with the token.
          </>
        }
      />
      <DataTable<APIToken>
        caption="API tokens"
        rowKey="id"
        rows={tokens.data}
        loading={tokens.isPending}
        fetching={tokens.isFetching}
        error={tokens.error}
        onRetry={() => void tokens.refetch()}
        emptyTitle="No API tokens"
        emptyDescription="Create one for Terraform or a script. It is shown once."
        columns={[
          {
            key: 'name',
            title: 'Name',
            render: (_, t) => (
              <>
                <strong>{t.name}</strong>
                {t.parent_token_id ? (
                  <div style={{ color: 'var(--hp-color-text-secondary)' }}>
                    Issued by token {tokenName(t.parent_token_id)}
                  </div>
                ) : null}
              </>
            ),
          },
          {
            key: 'hint',
            title: 'Token',
            render: (_, t) => <code className="hp-mono">hallpass_at_…{t.hint}</code>,
          },
          { key: 'operator', title: 'Acts for', render: (_, t) => <OperatorName id={t.operator_id} /> },
          { key: 'role', title: 'Role', render: (_, t) => roleLabel(t.role) },
          { key: 'state', title: 'Status', render: (_, t) => <TokenState token={t} now={now} /> },
          {
            key: 'expires',
            title: 'Expires',
            render: (_, t) =>
              t.never_expires || !t.expires_at ? (
                <StatusBadge tone="warning">Never</StatusBadge>
              ) : (
                formatDateTime(t.expires_at)
              ),
          },
          {
            key: 'used',
            title: 'Last used',
            render: (_, t) =>
              t.last_used_at ? `${formatDateTime(t.last_used_at)} from ${t.last_used_ip ?? '?'}` : 'Never',
          },
          {
            key: 'actions',
            title: <span className="hp-visually-hidden">Actions</span>,
            align: 'right',
            render: (_, t) =>
              t.revoked_at ? null : (
                <ConfirmAction<undefined>
                  label="Revoke"
                  title={`Revoke the token ${t.name}?`}
                  confirmLabel="Revoke"
                  buttonProps={{ size: 'small', 'aria-label': `Revoke token ${t.name}` }}
                  description="Anything using it stops working immediately, and so do the tokens it issued. This cannot be undone."
                  onConfirm={async () => {
                    await api.call('delete', '/api/v1/api-tokens/{id}', { path: { id: t.id } });
                    return undefined;
                  }}
                  onSuccess={() => {
                    void message.success(`Token ${t.name} revoked`);
                    void queryClient.invalidateQueries({ queryKey: qk.apiTokens });
                  }}
                />
              ),
          },
        ]}
      />
      <FormModal<TokenFormValues>
        open={creating}
        title="New API token"
        okText="Create token"
        formLabel="New API token"
        initialValues={{
          role: isAdmin ? 'administrator' : myRoles[0],
          expires_in_days: 90,
          never_expires: false,
        }}
        onCancel={() => {
          setCreating(false);
        }}
        onSubmit={async (values, { idempotencyKey }) => {
          const body = values.never_expires
            ? { name: values.name, role: values.role, never_expires: true }
            : { name: values.name, role: values.role, expires_in_days: values.expires_in_days };
          const res = await api.call('post', '/api/v1/api-tokens', { body, idempotencyKey });
          await queryClient.invalidateQueries({ queryKey: qk.apiTokens });
          setCreating(false);
          secret.show({
            title: `Token ${res.api_token.name}`,
            label: 'API token',
            description:
              'Copy it now: it is shown only once. Use it as a bearer token, for example HALLPASS_TOKEN for the Terraform provider.',
            values: [res.token],
          });
        }}
      >
        <Form.Item
          name="name"
          label="Name"
          extra="What uses it, e.g. terraform-prod."
          rules={[{ required: true, max: 100, whitespace: true }]}
        >
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item
          name="role"
          label="Role"
          extra={
            isAdmin
              ? 'Any role. Pick the least the automation needs, e.g. Auditor for a read-only integration.'
              : 'One of your own roles.'
          }
          rules={[{ required: true }]}
        >
          <Select options={roleChoices.map((r) => ({ value: r, label: roleLabel(r) }))} />
        </Form.Item>
        <Form.Item
          name="never_expires"
          label="Never expires"
          valuePropName="checked"
          extra="For Terraform or break-glass automation that must not stop on a date."
        >
          <Switch aria-label="Never expires" />
        </Form.Item>
        <Form.Item
          noStyle
          shouldUpdate={(a: TokenFormValues, b: TokenFormValues) => a.never_expires !== b.never_expires}
        >
          {({ getFieldValue }) =>
            getFieldValue('never_expires') ? (
              <Alert
                type="warning"
                showIcon
                title="A token that never expires"
                description="Anyone who obtains it can act with this role until you revoke it. Store it like a root password, watch when and where it was last used, and revoke it when it is no longer needed."
              />
            ) : (
              <Form.Item
                name="expires_in_days"
                label="Expires after (days)"
                extra="1 to 366 days. Rotate tokens before they expire."
                rules={[{ required: true, type: 'integer', min: 1, max: 366 }]}
              >
                <InputNumber min={1} max={366} precision={0} />
              </Form.Item>
            )
          }
        </Form.Item>
      </FormModal>
      {secret.dialog}
    </>
  );
}
