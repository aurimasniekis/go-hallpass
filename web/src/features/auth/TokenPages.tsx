import { Alert, Button, Form, Input, Result } from 'antd';
import { useState } from 'react';

import { api as defaultClient, type ApiClient } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { AuthLayout } from './AuthLayout';
import { NewPasswordFields } from './PasswordFields';

const PUBLIC_OPTS = { csrf: 'none', authRedirect: false, reauth: false } as const;

/**
 * Accept an invitation (`/invite/<token>`, from `POST /invitations`): choose a display name and password
 * (`POST /auth/invitations/{token}/accept`). The token stays in memory; the route removes it from the URL.
 */
export function AcceptInvitationPage({
  token,
  onSignIn,
  client = defaultClient,
}: {
  token: string;
  onSignIn: () => void;
  client?: ApiClient;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);

  const submit = async (values: { display_name: string; password: string }) => {
    setPending(true);
    setError(null);
    try {
      await client.call('post', '/api/v1/auth/invitations/{token}/accept', {
        path: { token },
        body: { display_name: values.display_name.trim(), password: values.password },
        ...PUBLIC_OPTS,
      });
      setDone(true);
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <AuthLayout title="Join Hallpass" subtitle="Finish setting up your operator account.">
      {token === '' ? (
        <Alert type="error" showIcon title="This invitation link is incomplete." />
      ) : done ? (
        <Result
          status="success"
          title="Account created"
          subTitle="Sign in with your email and new password. You may be asked to set up an authenticator."
          extra={
            <Button type="primary" onClick={onSignIn}>
              Sign in
            </Button>
          }
        />
      ) : (
        <Form<{ display_name: string; password: string }>
          layout="vertical"
          requiredMark={false}
          onFinish={(v) => void submit(v)}
          aria-label="Accept invitation"
        >
          <Form.Item
            label="Display name"
            name="display_name"
            rules={[{ required: true, message: 'Enter a display name' }]}
          >
            <Input autoComplete="name" />
          </Form.Item>
          <NewPasswordFields />
          {error !== null ? (
            <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
          ) : null}
          <Button type="primary" htmlType="submit" block loading={pending}>
            Create account
          </Button>
        </Form>
      )}
    </AuthLayout>
  );
}

/** Password reset (`/reset/<token>`, admin-issued, single use, 1 h): `POST /auth/reset/{token}`. */
export function ResetPasswordPage({
  token,
  onSignIn,
  client = defaultClient,
}: {
  token: string;
  onSignIn: () => void;
  client?: ApiClient;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);

  const submit = async (values: { password: string }) => {
    setPending(true);
    setError(null);
    try {
      await client.call('post', '/api/v1/auth/reset/{token}', {
        path: { token },
        body: { password: values.password },
        ...PUBLIC_OPTS,
      });
      setDone(true);
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <AuthLayout title="Reset password">
      {token === '' ? (
        <Alert type="error" showIcon title="This reset link is incomplete." />
      ) : done ? (
        <Result
          status="success"
          title="Password changed"
          subTitle="Your other sessions were signed out. Sign in with the new password."
          extra={
            <Button type="primary" onClick={onSignIn}>
              Sign in
            </Button>
          }
        />
      ) : (
        <Form<{ password: string }>
          layout="vertical"
          requiredMark={false}
          onFinish={(v) => void submit(v)}
          aria-label="Choose a new password"
        >
          <NewPasswordFields label="New password" />
          {error !== null ? (
            <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
          ) : null}
          <Button type="primary" htmlType="submit" block loading={pending}>
            Set password
          </Button>
        </Form>
      )}
    </AuthLayout>
  );
}
