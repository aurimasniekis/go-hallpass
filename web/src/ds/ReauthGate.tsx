import { Alert, Button, Divider, Form, Input, Modal, Space } from 'antd';
import { useEffect, useRef, useState, type ReactNode } from 'react';

import { api as defaultClient, type ApiClient } from '../api/client';
import { ApiError, errorMessage } from '../api/errors';
import type { AuthProviderSummary, Me } from '../api/types';
import { oidcStartUrl, rememberStepUpReturn } from '../features/auth/sso';

/**
 * Recent-authentication prompt (docs/PLAN.md §12.3/§12.4, HP-AUTH-014, HP-OIDC-013).
 *
 * Registered as the API client's `onReauthRequired` handler. When a request fails with
 * `reauth_required` or `mfa_required`, the client awaits this prompt; on success it refreshes the rotated
 * CSRF token and retries the original request exactly once. Cancelling rejects the original request.
 *
 * - Password (and break-glass) sessions: password plus TOTP/recovery code when MFA is enrolled
 *   (`POST /auth/reauth`).
 * - SSO sessions: step-up at the identity provider, a full-page navigation to
 *   `/auth/oidc/{slug}/start?purpose=stepup&return_to=<here>`. The original request is not retried
 *   (the page reloads); the operator repeats the action on return. When the provider cannot prove a fresh
 *   login (`mfa_required`), or the operator prefers, the TOTP fallback uses `POST /auth/reauth/totp`.
 * - Limited sessions (password accepted, MFA pending) are sent to `/login` to finish signing in.
 */

type Mode =
  | { kind: 'loading' }
  | { kind: 'error'; error: unknown }
  | { kind: 'limited' }
  | { kind: 'password'; me: Me }
  | { kind: 'sso'; me: Me; providers: readonly AuthProviderSummary[]; totp: boolean };

export interface ReauthGateProps {
  client?: ApiClient;
  /** Full-page navigation (overridable in tests). */
  navigate?: (url: string) => void;
  /** Current in-app location used as the step-up `return_to`. */
  currentPath?: () => string;
}

const defaultNavigate = (url: string) => {
  window.location.assign(url);
};
const defaultCurrentPath = () => `${window.location.pathname}${window.location.search}`;

interface PasswordValues {
  password: string;
  code?: string;
}

export function ReauthGate({
  client = defaultClient,
  navigate = defaultNavigate,
  currentPath = defaultCurrentPath,
}: ReauthGateProps) {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<Mode>({ kind: 'loading' });
  const [reason, setReason] = useState<'reauth' | 'mfa'>('reauth');
  const [ssoTotp, setSsoTotp] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const resolver = useRef<((accepted: boolean) => void) | null>(null);
  const [form] = Form.useForm<PasswordValues>();

  useEffect(
    () =>
      client.setHandlers({
        onReauthRequired: (cause: ApiError) =>
          new Promise<boolean>((resolve) => {
            resolver.current = resolve;
            setError(null);
            setSsoTotp(false);
            setReason(cause.isMfaRequired ? 'mfa' : 'reauth');
            setMode({ kind: 'loading' });
            setOpen(true);
            void (async () => {
              try {
                const me = await client.getMe({ authRedirect: false });
                if (me.session.limited) {
                  setMode({ kind: 'limited' });
                } else if (me.session.method === 'oidc') {
                  const config = await client.getAuthConfig();
                  setMode({ kind: 'sso', me, providers: config.providers, totp: me.operator.mfa_enrolled });
                } else {
                  setMode({ kind: 'password', me });
                }
              } catch (e) {
                setMode({ kind: 'error', error: e });
              }
            })();
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

  const run = async (call: () => Promise<unknown>) => {
    setPending(true);
    setError(null);
    try {
      await call();
      finish(true);
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  const submitPassword = (values: PasswordValues) =>
    run(() =>
      client.call('post', '/api/v1/auth/reauth', {
        body: { password: values.password, ...(values.code ? { code: values.code.trim() } : {}) },
        reauth: false,
        authRedirect: false,
      }),
    );

  const submitTotp = (values: { code: string }) =>
    run(() =>
      client.call('post', '/api/v1/auth/reauth/totp', {
        body: { code: values.code.trim() },
        reauth: false,
        authRedirect: false,
      }),
    );

  const stepUp = (slug: string) => {
    const here = currentPath();
    rememberStepUpReturn(here);
    finish(false);
    navigate(oidcStartUrl(slug, 'stepup', here));
  };

  const cancel = () => {
    if (!pending) {
      finish(false);
    }
  };

  const errorAlert =
    error !== null ? (
      <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
    ) : null;

  const footer = (submitLabel: string | null) => (
    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
      <Button onClick={cancel} disabled={pending}>
        Cancel
      </Button>
      {submitLabel ? (
        <Button type="primary" htmlType="submit" loading={pending}>
          {submitLabel}
        </Button>
      ) : null}
    </div>
  );

  let body: ReactNode;
  switch (mode.kind) {
    case 'loading':
      body = (
        <>
          <p role="status">Checking your session…</p>
          {footer(null)}
        </>
      );
      break;
    case 'error':
      body = (
        <>
          <Alert type="error" showIcon title={errorMessage(mode.error)} style={{ marginBottom: 16 }} />
          {footer(null)}
        </>
      );
      break;
    case 'limited':
      body = (
        <>
          <p>Your sign-in is not complete. Finish two-factor authentication to continue.</p>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <Button onClick={cancel}>Cancel</Button>
            <Button
              type="primary"
              onClick={() => {
                finish(false);
                navigate(`/login?next=${encodeURIComponent(currentPath())}`);
              }}
            >
              Go to sign-in
            </Button>
          </div>
        </>
      );
      break;
    case 'password': {
      const needsCode = mode.me.operator.mfa_enrolled;
      body = (
        <Form<PasswordValues>
          form={form}
          layout="vertical"
          requiredMark={false}
          onFinish={(values) => {
            void submitPassword(values);
          }}
          aria-label="Re-authenticate with password"
        >
          <p>
            {reason === 'mfa'
              ? 'This action needs a recent second-factor check. Enter your password and authenticator code.'
              : 'This action needs a recent sign-in. Enter your password to continue.'}
          </p>
          <Form.Item
            label="Password"
            name="password"
            rules={[{ required: true, message: 'Enter your password' }]}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          {needsCode ? (
            <Form.Item
              label="Authenticator or recovery code"
              name="code"
              rules={[{ required: true, message: 'Enter a code' }]}
            >
              <Input autoComplete="one-time-code" spellCheck={false} maxLength={32} />
            </Form.Item>
          ) : null}
          {errorAlert}
          {footer('Verify')}
        </Form>
      );
      break;
    }
    case 'sso':
      body =
        ssoTotp && mode.totp ? (
          <Form<{ code: string }>
            layout="vertical"
            requiredMark={false}
            onFinish={(values) => {
              void submitTotp(values);
            }}
            aria-label="Re-authenticate with authenticator code"
          >
            <p>Enter the code from your HallPass authenticator app, or a recovery code.</p>
            <Form.Item
              label="Authenticator or recovery code"
              name="code"
              rules={[{ required: true, message: 'Enter a code' }]}
            >
              <Input autoComplete="one-time-code" spellCheck={false} maxLength={32} />
            </Form.Item>
            {errorAlert}
            {footer('Verify')}
          </Form>
        ) : (
          <>
            <p>
              This action needs a recent sign-in. You will be sent to your identity provider and returned
              here; then repeat the action.
            </p>
            <Space orientation="vertical" style={{ width: '100%' }}>
              {mode.providers.length === 0 ? (
                <Alert type="warning" showIcon title="No SSO provider is enabled for step-up." />
              ) : (
                mode.providers.map((p) => (
                  <Button
                    key={p.slug}
                    block
                    onClick={() => {
                      stepUp(p.slug);
                    }}
                  >
                    Continue with {p.display_name}
                  </Button>
                ))
              )}
            </Space>
            {mode.totp ? (
              <>
                <Divider plain>or</Divider>
                <Button
                  block
                  type="link"
                  onClick={() => {
                    setSsoTotp(true);
                  }}
                >
                  Use my authenticator code instead
                </Button>
              </>
            ) : null}
            <div style={{ marginTop: 16 }}>{footer(null)}</div>
          </>
        );
      break;
  }

  return (
    <Modal
      open={open}
      title="Confirm it's you"
      onCancel={cancel}
      mask={{ closable: false }}
      closable={!pending}
      destroyOnHidden
      footer={null}
    >
      {body}
    </Modal>
  );
}
