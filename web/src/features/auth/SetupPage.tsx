import { Alert, Button, Form, Input, Steps } from 'antd';
import { useState } from 'react';

import { api as defaultClient, type ApiClient } from '../../api/client';
import { errorMessage } from '../../api/errors';
import type { BootstrapRequest } from '../../api/types';
import { AuthLayout } from './AuthLayout';
import { validatePasswordLength } from './password';

/**
 * First-run setup (docs/PLAN.md §12.2). `hallpass admin bootstrap` prints a one-time URL carrying the
 * setup token; the route strips it from the address bar on arrival (see routes/setup.tsx).
 *
 * WP19 scope: account step against a PROVISIONAL `POST /auth/bootstrap` body. TOTP enrollment, which
 * setup must force, is a placeholder until the backend enrollment API exists.
 */

interface SetupValues extends BootstrapRequest {
  confirm: string;
}

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
      await client.post('/auth/bootstrap', values, {
        csrf: 'pre-session',
        authRedirect: false,
        reauth: false,
      });
      setStep(1);
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
            label="Username"
            name="username"
            rules={[{ required: true, message: 'Choose a username' }]}
          >
            <Input autoComplete="username" autoCapitalize="none" spellCheck={false} />
          </Form.Item>
          <Form.Item
            label="Display name"
            name="display_name"
            rules={[{ required: true, message: 'Enter a display name' }]}
          >
            <Input autoComplete="name" />
          </Form.Item>
          <Form.Item
            label="Password"
            name="password"
            extra="12 to 1024 bytes. Long passphrases are encouraged."
            rules={[
              { required: true, message: 'Choose a password' },
              {
                validator: (_rule, value: unknown) => {
                  const problem = typeof value === 'string' ? validatePasswordLength(value) : null;
                  return problem ? Promise.reject(new Error(problem)) : Promise.resolve();
                },
              },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            label="Confirm password"
            name="confirm"
            dependencies={['password']}
            rules={[
              { required: true, message: 'Repeat the password' },
              ({ getFieldValue }) => ({
                validator: (_rule, value: unknown) =>
                  value === getFieldValue('password')
                    ? Promise.resolve()
                    : Promise.reject(new Error('Passwords do not match')),
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          {error !== null ? (
            <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
          ) : null}
          <Button type="primary" htmlType="submit" block loading={pending}>
            Create administrator
          </Button>
        </Form>
      ) : (
        <>
          <Alert
            type="warning"
            showIcon
            title="TOTP enrollment is not implemented in the UI yet"
            description="Setup must enroll an authenticator before the account is usable (docs/PLAN.md §12.2). This step is a placeholder until the enrollment API exists."
            style={{ marginBottom: 16 }}
          />
          <Button type="primary" block onClick={onDone}>
            Continue to sign in
          </Button>
        </>
      )}
    </AuthLayout>
  );
}
