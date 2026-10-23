import { Alert, Button, Form, Input, QRCode, Space } from 'antd';
import { useEffect, useRef, useState } from 'react';

import { api as defaultClient, type ApiClient } from '../../api/client';
import { errorMessage } from '../../api/errors';
import type { TOTPEnrollment } from '../../api/types';
import { CopyField } from '../../ds/CopyField';
import { OneTimeSecret } from '../../ds/OneTimeSecret';

/**
 * TOTP enrollment (HP-AUTH-006): `POST /me/mfa/totp` returns a secret and `otpauth://` URI, the
 * operator scans it (QR rendered locally, never sent anywhere) and confirms a code with
 * `POST /me/mfa/totp/confirm`, which returns recovery codes shown exactly once. Works for limited
 * sessions that must enroll before they are allowed in.
 */
export function TotpEnrollment({
  client = defaultClient,
  onDone,
  onCancel,
}: {
  client?: ApiClient;
  /** Called after the recovery codes were acknowledged. */
  onDone: () => void;
  onCancel?: () => void;
}) {
  const [enrollment, setEnrollment] = useState<TOTPEnrollment | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const started = useRef(false);

  const begin = async () => {
    setPending(true);
    setError(null);
    try {
      setEnrollment(await client.call('post', '/api/v1/me/mfa/totp', { reauth: false, authRedirect: false }));
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  useEffect(() => {
    // Start once on mount (StrictMode mounts twice in development).
    if (!started.current) {
      started.current = true;
      void begin();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- run once
  }, []);

  const confirm = async ({ code }: { code: string }) => {
    setPending(true);
    setError(null);
    try {
      const res = await client.call('post', '/api/v1/me/mfa/totp/confirm', {
        body: { code: code.trim() },
        reauth: false,
        authRedirect: false,
      });
      setCodes(res.codes);
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      {enrollment === null ? (
        error !== null ? (
          <Alert
            type="error"
            showIcon
            title="Could not start enrollment"
            description={errorMessage(error)}
            action={
              <Button size="small" onClick={() => void begin()}>
                Retry
              </Button>
            }
          />
        ) : (
          <p role="status">Preparing authenticator setup…</p>
        )
      ) : (
        <>
          <p>
            Scan this code with an authenticator app (or enter the secret manually), then enter the 6-digit
            code it shows.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <QRCode
              value={enrollment.uri}
              type="svg"
              size={176}
              bordered
              aria-label="Authenticator QR code"
            />
          </div>
          <CopyField label="Secret" value={enrollment.secret} />
          <Form<{ code: string }>
            layout="vertical"
            requiredMark={false}
            onFinish={(v) => void confirm(v)}
            aria-label="Confirm authenticator"
          >
            <Form.Item
              label="Code from your app"
              name="code"
              rules={[{ required: true, message: 'Enter the code from your authenticator' }]}
            >
              <Input inputMode="numeric" autoComplete="one-time-code" maxLength={8} spellCheck={false} />
            </Form.Item>
            {error !== null ? (
              <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
            ) : null}
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              {onCancel ? (
                <Button onClick={onCancel} disabled={pending}>
                  Cancel
                </Button>
              ) : null}
              <Button type="primary" htmlType="submit" loading={pending}>
                Confirm
              </Button>
            </div>
          </Form>
        </>
      )}
      <OneTimeSecret
        open={codes !== null}
        title="Recovery codes"
        label="Recovery codes"
        description="Each code signs you in once if you lose your authenticator. Store them offline."
        values={codes ?? []}
        onClose={() => {
          setCodes(null);
          onDone();
        }}
      />
    </Space>
  );
}
