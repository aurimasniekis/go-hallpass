import { Alert, Button, Form, Input, Result, Space } from 'antd';
import { useState } from 'react';

import { api as defaultClient, type ApiClient } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { AuthLayout } from './AuthLayout';
import { TotpEnrollment } from './TotpEnrollment';

/**
 * Break-glass recovery (HP-AUTH-016, docs/operator/backup.md). `hallpass admin recover` prints a
 * single-use `/recover?token=…` link (30 minutes); the route strips the token from the address bar.
 *
 * 1. The operator confirms and the page redeems the token (`POST /auth/recover`). The server revokes the
 *    account's other sessions and removes its TOTP factor and recovery codes.
 * 2. When policy requires MFA, the recovery session is limited until a new authenticator is enrolled.
 * 3. Accounts with a local password get a one-time reset link, so the administrator can set a password
 *    they know (using it ends every session, including the recovery one).
 *
 * Nothing is redeemed automatically on page load: link scanners and prefetchers must not burn the token.
 */

const PUBLIC_OPTS = { csrf: 'none', authRedirect: false, reauth: false } as const;

type Step = 'token' | 'enroll' | 'done';

export function RecoverPage({
  initialToken,
  onDone,
  onResetPassword,
  client = defaultClient,
}: {
  initialToken: string;
  /** Continue into the application with the recovery session. */
  onDone: () => void;
  /** Open the password reset page (`/reset/<token>`). */
  onResetPassword: (url: string) => void;
  client?: ApiClient;
}) {
  const [step, setStep] = useState<Step>('token');
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [resetUrl, setResetUrl] = useState<string | null>(null);

  const redeem = async ({ token }: { token: string }) => {
    setPending(true);
    setError(null);
    try {
      const res = await client.call('post', '/api/v1/auth/recover', {
        body: { token: token.trim() },
        ...PUBLIC_OPTS,
      });
      client.setCsrfToken(res.me.csrf_token);
      setResetUrl(res.password_reset?.url ?? null);
      setStep(res.must_enroll ? 'enroll' : 'done');
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <AuthLayout
      title="Break-glass recovery"
      subtitle="Single-use administrator recovery issued on the server."
    >
      {step === 'token' ? (
        <Form<{ token: string }>
          layout="vertical"
          requiredMark={false}
          initialValues={{ token: initialToken }}
          onFinish={(v) => void redeem(v)}
          aria-label="Redeem recovery login"
        >
          <Alert
            type="warning"
            showIcon
            title="This signs you in with a break-glass session"
            description="Other sessions of this account end, and its authenticator and recovery codes are removed. The use is audited and raises an alert until an administrator acknowledges it."
            style={{ marginBottom: 16 }}
          />
          <Form.Item
            label="Recovery token"
            name="token"
            extra="Printed by `hallpass admin recover`. Valid once, for 30 minutes."
            rules={[{ required: true, message: 'Enter the recovery token' }]}
          >
            <Input.Password autoComplete="off" spellCheck={false} />
          </Form.Item>
          {error !== null ? (
            <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
          ) : null}
          <Button type="primary" htmlType="submit" block loading={pending}>
            Use recovery login
          </Button>
        </Form>
      ) : step === 'enroll' ? (
        <>
          <Alert
            type="info"
            showIcon
            title="Set up a new authenticator"
            description="This account requires two-factor authentication. Enroll a new authenticator to continue."
            style={{ marginBottom: 16 }}
          />
          <TotpEnrollment
            client={client}
            limited
            onDone={() => {
              setStep('done');
            }}
          />
        </>
      ) : (
        <Result
          status="success"
          title="Signed in for recovery"
          subTitle="Review the audit log and rotate credentials as needed. Acknowledge the break-glass alert when done."
          extra={
            <Space orientation="vertical" size={12} style={{ width: '100%' }}>
              {resetUrl ? (
                <Alert
                  type="warning"
                  showIcon
                  title="Set a new password"
                  description="Use the one-time link (valid for 1 hour) to set a password you know. It signs you out of every session, including this one, so finish urgent recovery work first."
                  action={
                    <Button
                      size="small"
                      onClick={() => {
                        onResetPassword(resetUrl);
                      }}
                    >
                      Set password
                    </Button>
                  }
                />
              ) : null}
              <Button type="primary" onClick={onDone}>
                Continue to HallPass
              </Button>
            </Space>
          }
        />
      )}
    </AuthLayout>
  );
}
