import { MailOutlined, PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Alert, Button, Checkbox, Form, Input, Modal, Select, Space, type TableColumnsType } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { operatorsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Operator } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { applyFieldErrors } from '../../lib/formErrors';
import { formatDateTime } from '../../lib/format';
import { newIdempotencyKey } from '../../lib/idempotency';
import { usePermissions } from '../../lib/usePermissions';
import { useSseStatus } from '../../stores/sse';
import { OPERATOR_ROLES, roleLabel, shareableLink } from './roles';
import { useOneTimeSecret } from './useOneTimeSecret';

const ROLE_SELECT_OPTIONS = OPERATOR_ROLES.map((r) => ({
  value: r.value,
  label: `${r.label} — ${r.description}`,
}));

interface CreateValues {
  email: string;
  display_name: string;
  roles: string[];
  mfa_required: boolean;
}

interface InviteValues {
  email: string;
  roles: string[];
}

/** Create-operator dialog. The server never sets a password here: the new operator needs a reset token. */
function CreateOperatorDialog({
  open,
  onClose,
  onCreated,
}: {
  open: boolean;
  onClose: () => void;
  onCreated: (op: Operator) => void;
}) {
  const [form] = Form.useForm<CreateValues>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);

  const submit = async (values: CreateValues) => {
    setPending(true);
    setError(null);
    try {
      const op = await api.call('post', '/api/v1/operators', {
        body: {
          email: values.email.trim(),
          display_name: values.display_name.trim(),
          roles: values.roles,
          mfa_required: values.mfa_required,
        },
        idempotencyKey,
      });
      form.resetFields();
      setIdempotencyKey(newIdempotencyKey());
      onCreated(op);
    } catch (e) {
      applyFieldErrors(form, e);
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Create operator"
      onCancel={() => {
        if (!pending) {
          setError(null);
          onClose();
        }
      }}
      okText="Create"
      okButtonProps={{ loading: pending, htmlType: 'submit', form: 'create-operator' }}
      cancelButtonProps={{ disabled: pending }}
      destroyOnHidden
    >
      <Form<CreateValues>
        id="create-operator"
        form={form}
        layout="vertical"
        requiredMark={false}
        initialValues={{ roles: ['viewer'], mfa_required: true }}
        onFinish={(v) => void submit(v)}
        aria-label="Create operator"
      >
        <Form.Item
          label="Email"
          name="email"
          rules={[{ required: true, type: 'email', message: 'Enter a valid email' }]}
        >
          <Input type="email" autoComplete="off" spellCheck={false} />
        </Form.Item>
        <Form.Item
          label="Display name"
          name="display_name"
          rules={[{ required: true, message: 'Enter a name' }]}
        >
          <Input autoComplete="off" />
        </Form.Item>
        <Form.Item label="Roles" name="roles">
          <Select mode="multiple" options={ROLE_SELECT_OPTIONS} aria-label="Roles" />
        </Form.Item>
        <Form.Item name="mfa_required" valuePropName="checked">
          <Checkbox>Require two-factor authentication</Checkbox>
        </Form.Item>
        <Alert
          type="info"
          showIcon
          title="No password is set"
          description="After creating the account, issue a one-time reset link so the operator can choose a password, or use an invitation instead."
        />
        {error !== null ? (
          <Alert type="error" showIcon title={errorMessage(error)} style={{ marginTop: 12 }} />
        ) : null}
      </Form>
    </Modal>
  );
}

function InviteDialog({
  open,
  onClose,
  onInvited,
}: {
  open: boolean;
  onClose: () => void;
  onInvited: (link: string, email: string) => void;
}) {
  const [form] = Form.useForm<InviteValues>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);

  const submit = async (values: InviteValues) => {
    setPending(true);
    setError(null);
    try {
      const res = await api.call('post', '/api/v1/invitations', {
        body: { email: values.email.trim(), roles: values.roles },
        idempotencyKey,
      });
      form.resetFields();
      setIdempotencyKey(newIdempotencyKey());
      onInvited(shareableLink(res.url, res.token), values.email.trim());
    } catch (e) {
      applyFieldErrors(form, e);
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Invite operator"
      onCancel={() => {
        if (!pending) {
          setError(null);
          onClose();
        }
      }}
      okText="Create invitation"
      okButtonProps={{ loading: pending, htmlType: 'submit', form: 'invite-operator' }}
      cancelButtonProps={{ disabled: pending }}
      destroyOnHidden
    >
      <Form<InviteValues>
        id="invite-operator"
        form={form}
        layout="vertical"
        requiredMark={false}
        initialValues={{ roles: ['viewer'] }}
        onFinish={(v) => void submit(v)}
        aria-label="Invite operator"
      >
        <p>The invitation link is single use and expires after 72 hours. Send it over a trusted channel.</p>
        <Form.Item
          label="Email"
          name="email"
          rules={[{ required: true, type: 'email', message: 'Enter a valid email' }]}
        >
          <Input type="email" autoComplete="off" spellCheck={false} />
        </Form.Item>
        <Form.Item label="Roles" name="roles">
          <Select mode="multiple" options={ROLE_SELECT_OPTIONS} aria-label="Roles" />
        </Form.Item>
        {error !== null ? <Alert type="error" showIcon title={errorMessage(error)} /> : null}
      </Form>
    </Modal>
  );
}

export function OperatorsPage() {
  const { can, loading: permsLoading } = usePermissions();
  const allowed = can('operators.manage');
  const operators = useQuery({ ...operatorsQueryOptions(), enabled: allowed });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const sse = useSseStatus();
  const [dialog, setDialog] = useState<'create' | 'invite' | null>(null);
  const [created, setCreated] = useState<Operator | null>(null);
  const secret = useOneTimeSecret();

  if (permsLoading) {
    return null;
  }
  if (!allowed) {
    return (
      <>
        <PageHeader title="Operators" />
        <PermissionDenied />
      </>
    );
  }

  const columns: TableColumnsType<Operator> = [
    {
      key: 'name',
      title: 'Name',
      render: (_, op) => (
        <Link to="/operators/$id" params={{ id: op.id }}>
          {op.display_name}
        </Link>
      ),
    },
    { key: 'email', title: 'Email', render: (_, op) => op.email ?? '—' },
    {
      key: 'roles',
      title: 'Roles',
      render: (_, op) => (op.roles.length ? op.roles.map(roleLabel).join(', ') : 'No roles'),
    },
    { key: 'provisioned', title: 'Provisioned', dataIndex: 'provisioned_via' },
    {
      key: 'enabled',
      title: 'Status',
      render: (_, op) =>
        op.enabled ? (
          <StatusBadge tone="success">Enabled</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">Disabled</StatusBadge>
        ),
    },
    {
      key: 'mfa',
      title: 'Two-factor',
      render: (_, op) =>
        op.mfa_enrolled ? (
          <StatusBadge tone="success">Enrolled</StatusBadge>
        ) : op.mfa_required ? (
          <StatusBadge tone="warning">Required, not enrolled</StatusBadge>
        ) : (
          <StatusBadge tone="neutral">Not enrolled</StatusBadge>
        ),
    },
    { key: 'last', title: 'Last sign-in', render: (_, op) => formatDateTime(op.last_login_at) },
  ];

  return (
    <>
      <PageHeader
        title="Operators"
        description="Operator accounts, roles and invitations."
        extra={
          <Space>
            <Button
              icon={<MailOutlined />}
              onClick={() => {
                setDialog('invite');
              }}
            >
              Invite
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => {
                setDialog('create');
              }}
            >
              Create operator
            </Button>
          </Space>
        }
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
          style={{ marginBottom: 16 }}
          title={`Created ${created.display_name}`}
          description="The account has no password yet. Issue a one-time reset link from the operator's page so they can set one."
          action={
            <Button
              size="small"
              onClick={() => void navigate({ to: '/operators/$id', params: { id: created.id } })}
            >
              Open
            </Button>
          }
        />
      ) : null}
      <DataTable<Operator>
        caption="Operators"
        columns={columns}
        rows={operators.data?.items}
        rowKey="id"
        loading={operators.isPending}
        fetching={operators.isFetching}
        error={operators.error}
        onRetry={() => void operators.refetch()}
        stale={sse === 'stale' || sse === 'disconnected'}
        emptyTitle="No operators"
      />
      <CreateOperatorDialog
        open={dialog === 'create'}
        onClose={() => {
          setDialog(null);
        }}
        onCreated={(op) => {
          setDialog(null);
          setCreated(op);
          void queryClient.invalidateQueries({ queryKey: qk.operators });
        }}
      />
      <InviteDialog
        open={dialog === 'invite'}
        onClose={() => {
          setDialog(null);
        }}
        onInvited={(link, email) => {
          setDialog(null);
          secret.show({
            title: 'Invitation link',
            label: 'Invitation link',
            description: `Send this link to ${email}. It is single use and expires in 72 hours.`,
            values: [link],
          });
        }}
      />
      {secret.dialog}
    </>
  );
}
