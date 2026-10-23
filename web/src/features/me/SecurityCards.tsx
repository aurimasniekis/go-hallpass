import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Form, Input, Modal, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { authConfigQueryOptions, myIdentitiesQueryOptions, mySessionsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Me } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { applyFieldErrors } from '../../lib/formErrors';
import { NewPasswordFields } from '../auth/PasswordFields';
import { oidcStartUrl } from '../auth/sso';
import { TotpEnrollment } from '../auth/TotpEnrollment';
import { IdentitiesTable, WebSessionsTable } from '../operators/tables';
import { useOneTimeSecret } from '../operators/useOneTimeSecret';

/** Own web sessions; other sessions can be revoked individually (the current one via Sign out). */
export function MySessions() {
  const sessions = useQuery(mySessionsQueryOptions());
  const queryClient = useQueryClient();
  return (
    <WebSessionsTable
      caption="My web sessions"
      rows={sessions.data?.items}
      loading={sessions.isPending}
      error={sessions.error}
      onRetry={() => void sessions.refetch()}
      action={(s) =>
        s.current ? (
          <span>Use Sign out</span>
        ) : (
          <ConfirmAction
            label="Revoke"
            title="Revoke session"
            description="That browser is signed out immediately."
            confirmLabel="Revoke"
            buttonProps={{ size: 'small' }}
            onConfirm={() => api.call('delete', '/api/v1/me/sessions/{id}', { path: { id: s.id } })}
            onSuccess={() => {
              void queryClient.invalidateQueries({ queryKey: qk.mySessions });
            }}
          />
        )
      }
    />
  );
}

interface PasswordValues {
  current_password: string;
  new_password: string;
  confirm: string;
}

/** Password change (HP-AUTH-009): requires the current password. */
export function PasswordChange() {
  const [form] = Form.useForm<PasswordValues>();
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);

  const submit = async (values: PasswordValues) => {
    setPending(true);
    setError(null);
    setDone(false);
    try {
      await api.call('post', '/api/v1/me/password', {
        body: { current_password: values.current_password, new_password: values.new_password },
      });
      form.resetFields();
      setDone(true);
      await queryClient.invalidateQueries({ queryKey: qk.mySessions });
    } catch (e) {
      applyFieldErrors(form, e);
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Form<PasswordValues>
      form={form}
      layout="vertical"
      requiredMark={false}
      onFinish={(v) => void submit(v)}
      aria-label="Change password"
      style={{ maxWidth: 420 }}
    >
      <Form.Item
        label="Current password"
        name="current_password"
        rules={[{ required: true, message: 'Enter your current password' }]}
      >
        <Input.Password autoComplete="current-password" />
      </Form.Item>
      <NewPasswordFields name="new_password" label="New password" />
      {error !== null ? (
        <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
      ) : null}
      {done ? (
        <Alert
          type="success"
          showIcon
          title="Password changed"
          description="Your other sessions may have been signed out."
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <Button type="primary" htmlType="submit" loading={pending}>
        Change password
      </Button>
    </Form>
  );
}

/** TOTP enrollment, disabling and recovery-code regeneration (HP-AUTH-006/007/010). */
export function TwoFactor({ me }: { me: Me }) {
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const [enrolling, setEnrolling] = useState(false);
  const secret = useOneTimeSecret();
  const op = me.operator;

  if (!op.mfa_enrolled) {
    return (
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <Alert
          type={op.mfa_required ? 'warning' : 'info'}
          showIcon
          title="Two-factor authentication is not set up"
          description={
            op.mfa_required
              ? 'Your account requires an authenticator app.'
              : 'Add an authenticator app to protect your account and to confirm sensitive actions.'
          }
        />
        <Button
          type="primary"
          onClick={() => {
            setEnrolling(true);
          }}
        >
          Set up authenticator
        </Button>
        <Modal
          open={enrolling}
          title="Set up authenticator"
          footer={null}
          destroyOnHidden
          onCancel={() => {
            setEnrolling(false);
          }}
        >
          <TotpEnrollment
            onCancel={() => {
              setEnrolling(false);
            }}
            onDone={() => {
              setEnrolling(false);
              void queryClient.invalidateQueries({ queryKey: qk.me });
              void queryClient.invalidateQueries({ queryKey: qk.mySessions });
              void message.success('Two-factor authentication is on');
            }}
          />
        </Modal>
      </Space>
    );
  }

  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <p style={{ margin: 0 }}>
        An authenticator app is enrolled. Recovery codes let you sign in if you lose it.
      </p>
      <Space wrap>
        <ConfirmAction
          label="Regenerate recovery codes"
          title="Regenerate recovery codes"
          description="Your existing recovery codes stop working immediately. The new codes are shown once."
          confirmLabel="Regenerate"
          danger={false}
          onConfirm={() => api.call('post', '/api/v1/me/recovery-codes')}
          onSuccess={(res) => {
            secret.show({
              title: 'New recovery codes',
              label: 'Recovery codes',
              description: 'Each code signs you in once. Store them offline.',
              values: res.codes,
            });
          }}
        />
        <ConfirmAction
          label="Disable two-factor"
          title="Disable two-factor authentication"
          description="Your account will be protected by the password alone, and your other sessions are signed out."
          confirmLabel="Disable"
          disabled={op.mfa_required}
          onConfirm={() => api.call('delete', '/api/v1/me/mfa/totp')}
          onSuccess={() => {
            void queryClient.invalidateQueries({ queryKey: qk.me });
            void message.success('Two-factor authentication is off');
          }}
        />
      </Space>
      {op.mfa_required ? (
        <p style={{ margin: 0 }}>
          Two-factor authentication is required for your account and cannot be disabled.
        </p>
      ) : null}
      {secret.dialog}
    </Space>
  );
}

/** Linked SSO identities and self-service linking through the provider (purpose=link). */
export function MyIdentities({ me }: { me: Me }) {
  const identities = useQuery(myIdentitiesQueryOptions());
  const config = useQuery(authConfigQueryOptions());
  const providers = config.data?.providers ?? [];
  const mfaSatisfied =
    me.session.method === 'oidc' || Boolean(me.session.mfa_at) || !me.operator.mfa_enrolled;
  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <IdentitiesTable
        caption="My SSO identities"
        rows={identities.data?.items}
        loading={identities.isPending}
        error={identities.error}
        onRetry={() => void identities.refetch()}
      />
      {providers.length > 0 ? (
        <>
          <p style={{ margin: 0 }}>
            Link another identity: you will sign in at the provider (a fresh login is required) and return
            here.
            {mfaSatisfied ? '' : ' Linking needs a session that completed two-factor authentication.'}
          </p>
          <Space wrap>
            {providers.map((p) => (
              <Button
                key={p.slug}
                onClick={() => {
                  window.location.assign(oidcStartUrl(p.slug, 'link', '/me'));
                }}
              >
                Link {p.display_name}
              </Button>
            ))}
          </Space>
        </>
      ) : config.isSuccess ? (
        <p style={{ margin: 0 }}>No SSO provider is enabled.</p>
      ) : null}
    </Space>
  );
}
