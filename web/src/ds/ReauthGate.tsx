import { Alert, Button, Form, Input, Modal } from 'antd';
import { useEffect, useRef, useState } from 'react';

import { api as defaultClient, type ApiClient } from '../api/client';
import { errorMessage } from '../api/errors';
import type { ReauthRequest } from '../api/types';

/**
 * Recent-authentication prompt (docs/PLAN.md §12.3, HP-AUTH-014).
 *
 * Registers itself as the API client's `onReauthRequired` handler. When a request fails with
 * `reauth_required`, the client awaits this prompt; on success it refreshes the rotated CSRF token
 * and retries the original request exactly once.
 *
 * PLACEHOLDER SCOPE (WP19): password (+ optional TOTP) against `POST /auth/reauth` with a provisional
 * body. OIDC step-up (docs/PLAN.md §12.4) is not implemented yet.
 */
export function ReauthGate({ client = defaultClient }: { client?: ApiClient }) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const resolver = useRef<((accepted: boolean) => void) | null>(null);
  const [form] = Form.useForm<ReauthRequest>();

  useEffect(
    () =>
      client.setHandlers({
        onReauthRequired: () =>
          new Promise<boolean>((resolve) => {
            resolver.current = resolve;
            setError(null);
            setOpen(true);
          }),
      }),
    [client],
  );

  const finish = (accepted: boolean) => {
    resolver.current?.(accepted);
    resolver.current = null;
    setOpen(false);
    form.resetFields();
  };

  const submit = async (values: ReauthRequest) => {
    setPending(true);
    setError(null);
    try {
      const body: ReauthRequest = { password: values.password };
      if (values.totp_code) {
        body.totp_code = values.totp_code.trim();
      }
      await client.post('/auth/reauth', body, { reauth: false, authRedirect: false });
      finish(true);
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      open={open}
      title="Confirm it's you"
      onCancel={() => {
        if (!pending) {
          finish(false);
        }
      }}
      mask={{ closable: false }}
      closable={!pending}
      destroyOnHidden
      footer={null}
    >
      <p>This action needs a recent sign-in. Enter your password to continue.</p>
      <Form<ReauthRequest>
        form={form}
        layout="vertical"
        requiredMark={false}
        onFinish={(values) => {
          void submit(values);
        }}
      >
        <Form.Item
          label="Password"
          name="password"
          rules={[{ required: true, message: 'Enter your password' }]}
        >
          <Input.Password autoComplete="current-password" />
        </Form.Item>
        <Form.Item label="Authenticator code (if MFA is enrolled)" name="totp_code">
          <Input inputMode="numeric" autoComplete="one-time-code" maxLength={12} />
        </Form.Item>
        {error !== null ? (
          <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
        ) : null}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button
            onClick={() => {
              finish(false);
            }}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button type="primary" htmlType="submit" loading={pending}>
            Verify
          </Button>
        </div>
      </Form>
    </Modal>
  );
}
