import { Alert, Button, Form, Input, Steps } from 'antd';
import { useState } from 'react';

import { api as defaultClient, type ApiClient } from '../../api/client';
import { errorMessage } from '../../api/errors';
import type { BootstrapRequest } from '../../api/types';
import { AuthLayout } from './AuthLayout';
import { NewPasswordFields } from './PasswordFields';
import { TotpEnrollment } from './TotpEnrollment';

/**
 * First-run setup (docs/PLAN.md §12.2). `hallpass admin bootstrap` prints a one-time URL carrying the
 * setup token; the route strips it from the address bar on arrival (see routes/setup.tsx).
 *
 * 1. `POST /auth/bootstrap` creates the first administrator (MFA required).
 * 2. The page signs in with the same credentials (`POST /auth/login` → `must_enroll`), held in memory
 *    only for this step, and runs TOTP enrollment; recovery codes are shown once.
 */

interface SetupValues extends BootstrapRequest {
  confirm: string;
}

const PUBLIC_OPTS = { csrf: 'none', authRedirect: false, reauth: false } as const;

export function SetupPage({
  initialToken,
  onDone,
  client = defaultClient,
}: {
  initialToken: string;
  onDone: () => void;
  client?: ApiClient;
}) {
  const [step, setStep] = useState(0);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async ({ confirm: _confirm, ...values }: SetupValues) => {
    setPending(true);
    setError(null);
    try {
      const body = { ...values, email: values.email.trim(), display_name: values.display_name.trim() };
      await client.call('post', '/api/v1/auth/bootstrap', { body, ...PUBLIC_OPTS });
      const login = await client.call('post', '/api/v1/auth/login', {
        body: { email: body.email, password: body.password },
        ...PUBLIC_OPTS,
      });
      client.setCsrfToken(login.me.csrf_token);
      if (login.must_enroll) {
        setStep(1);
      } else {
        // Already enrolled (should not happen for a fresh administrator); continue to sign-in.
        onDone();
      }
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <AuthLayout title="Set up Hallpass" subtitle="Create the first administrator account.">
      <Steps
        size="small"
        current={step}
        style={{ marginBottom: 24 }}
        items={[{ title: 'Administrator' }, { title: 'Two-factor authentication' }]}
      />
      {step === 0 ? (
        <Form<SetupValues>
          layout="vertical"
          requiredMark={false}
          initialValues={{ token: initialToken }}
          onFinish={(values) => {
            void submit(values);
          }}
          aria-label="Create administrator"
        >
          <Form.Item
            label="Setup token"
            name="token"
            extra="Printed by `hallpass admin bootstrap`. Valid only until the first administrator exists."
            rules={[{ required: true, message: 'Enter the setup token' }]}
          >
            <Input.Password autoComplete="off" spellCheck={false} />
          </Form.Item>
          <Form.Item
            label="Email"
            name="email"
            rules={[{ required: true, type: 'email', message: 'Enter a valid email address' }]}
          >
            <Input type="email" autoComplete="username" autoCapitalize="none" spellCheck={false} />
          </Form.Item>
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
            Create administrator
          </Button>
        </Form>
      ) : (
        <TotpEnrollment client={client} onDone={onDone} />
      )}
    </AuthLayout>
  );
}
