import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Divider, Form, Input } from 'antd';
import { useEffect, useRef, useState } from 'react';
import type { InputRef } from 'antd';

import { api as defaultClient, type ApiClient } from '../../api/client';
import { errorMessage, isApiError } from '../../api/errors';
import { authConfigQueryOptions } from '../../api/queries';
import type {
  AuthConfig,
  LoginRequest,
  LoginResponse,
  MfaRequest,
  OidcProviderSummary,
} from '../../api/types';
import { ErrorState, LoadingState } from '../../ds/states';
import { AuthLayout } from './AuthLayout';

/**
 * Login (docs/PLAN.md §12.1; HP-UI-006). Renders from `GET /auth/config`:
 * local form only, SSO buttons only, or both. A `mfa_required` answer moves to the TOTP step.
 *
 * PROVISIONAL backend contract: request bodies, the `return_to` OIDC start parameter and the
 * login-CSRF transport are not yet fixed in api/openapi.yaml (see src/api/types.ts).
 */

const AUTH_OPTS = { csrf: 'pre-session', authRedirect: false, reauth: false } as const;

export function oidcStartUrl(provider: OidcProviderSummary, next: string): string {
  return `/api/v1/auth/oidc/${encodeURIComponent(provider.id)}/start?return_to=${encodeURIComponent(next)}`;
}

function LocalLoginForm({
  client,
  onMfaRequired,
  onSignedIn,
}: {
  client: ApiClient;
  onMfaRequired: () => void;
  onSignedIn: () => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (values: LoginRequest) => {
    setPending(true);
    setError(null);
    try {
      const res = await client.post<LoginResponse | undefined>('/auth/login', values, AUTH_OPTS);
      if (res?.mfa_required) {
        onMfaRequired();
      } else {
        onSignedIn();
      }
    } catch (e) {
      if (isApiError(e) && e.code === 'mfa_required') {
        onMfaRequired();
      } else {
        setError(e);
      }
    } finally {
      setPending(false);
    }
  };

  return (
    <Form<LoginRequest>
      layout="vertical"
      requiredMark={false}
      onFinish={(values) => {
        void submit(values);
      }}
      aria-label="Sign in with username and password"
    >
      <Form.Item
        label="Username"
        name="username"
        rules={[{ required: true, message: 'Enter your username' }]}
      >
        <Input autoComplete="username" autoCapitalize="none" spellCheck={false} />
      </Form.Item>
      <Form.Item
        label="Password"
        name="password"
        rules={[{ required: true, message: 'Enter your password' }]}
      >
        <Input.Password autoComplete="current-password" />
      </Form.Item>
      {error !== null ? (
        <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
      ) : null}
      <Button type="primary" htmlType="submit" block loading={pending}>
        Sign in
      </Button>
    </Form>
  );
}

function MfaForm({
  client,
  onSignedIn,
  onBack,
}: {
  client: ApiClient;
  onSignedIn: () => void;
  onBack: () => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const codeInput = useRef<InputRef>(null);

  // Move focus to the code field when this step replaces the password form.
  useEffect(() => {
    codeInput.current?.focus();
  }, []);

  const submit = async (values: MfaRequest) => {
    setPending(true);
    setError(null);
    try {
      await client.post('/auth/mfa', { code: values.code.trim() }, AUTH_OPTS);
      onSignedIn();
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Form<MfaRequest>
      layout="vertical"
      requiredMark={false}
      onFinish={(values) => {
        void submit(values);
      }}
      aria-label="Two-factor authentication"
    >
      <p>Enter the code from your authenticator app, or one of your recovery codes.</p>
      <Form.Item
        label="Authentication code"
        name="code"
        rules={[{ required: true, message: 'Enter a code' }]}
      >
        <Input
          ref={codeInput}
          autoComplete="one-time-code"
          inputMode="text"
          spellCheck={false}
          maxLength={32}
        />
      </Form.Item>
      {error !== null ? (
        <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
      ) : null}
      <Button type="primary" htmlType="submit" block loading={pending}>
        Verify
      </Button>
      <Button type="link" block onClick={onBack} disabled={pending} style={{ marginTop: 8 }}>
        Use a different account
      </Button>
    </Form>
  );
}

function SsoButtons({ providers, next }: { providers: readonly OidcProviderSummary[]; next: string }) {
  return (
    <nav aria-label="Single sign-on providers" style={{ display: 'grid', gap: 8 }}>
      {providers.map((p) => (
        <Button key={p.id} block href={oidcStartUrl(p, next)}>
          Sign in with {p.display_name}
        </Button>
      ))}
    </nav>
  );
}

export function LoginForms({
  config,
  next,
  onSignedIn,
  client = defaultClient,
}: {
  config: AuthConfig;
  next: string;
  onSignedIn: () => void;
  client?: ApiClient;
}) {
  const [step, setStep] = useState<'credentials' | 'mfa'>('credentials');
  const providers = config.oidc_providers;

  if (step === 'mfa') {
    return (
      <MfaForm
        client={client}
        onSignedIn={onSignedIn}
        onBack={() => {
          setStep('credentials');
        }}
      />
    );
  }
  if (!config.local_enabled && providers.length === 0) {
    return (
      <Alert
        type="warning"
        showIcon
        title="No sign-in method is enabled"
        description="An administrator can restore access with `hallpass admin recover` on the server."
      />
    );
  }
  return (
    <>
      {config.local_enabled ? (
        <LocalLoginForm
          client={client}
          onSignedIn={onSignedIn}
          onMfaRequired={() => {
            setStep('mfa');
          }}
        />
      ) : null}
      {config.local_enabled && providers.length > 0 ? <Divider plain>or</Divider> : null}
      {providers.length > 0 ? <SsoButtons providers={providers} next={next} /> : null}
    </>
  );
}

export function LoginPage({ next, onSignedIn }: { next: string; onSignedIn: () => void }) {
  const config = useQuery(authConfigQueryOptions());
  return (
    <AuthLayout title="Sign in to Hallpass">
      {config.isPending ? (
        <LoadingState label="Loading sign-in options…" />
      ) : config.isError ? (
        <ErrorState
          error={config.error}
          title="Sign-in options unavailable"
          onRetry={() => {
            void config.refetch();
          }}
        />
      ) : (
        <LoginForms config={config.data} next={next} onSignedIn={onSignedIn} />
      )}
    </AuthLayout>
  );
}
