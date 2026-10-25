import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Divider, Form, Input } from 'antd';
import type { InputRef } from 'antd';
import { useEffect, useRef, useState } from 'react';

import { api as defaultClient, type ApiClient } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { authConfigQueryOptions } from '../../api/queries';
import type { AuthConfig, AuthProviderSummary, LoginRequest, Me } from '../../api/types';
import { ErrorState, LoadingState } from '../../ds/states';
import { AuthLayout } from './AuthLayout';
import { oidcStartUrl, ssoErrorMessage, takeStepUpReturn, wasSignedOut } from './sso';
import { TotpEnrollment } from './TotpEnrollment';

/**
 * Login (docs/PLAN.md §12.1; HP-UI-006). Renders from `GET /auth/config`: local form only, SSO buttons
 * only, or both. `POST /auth/login` returns `{mfa_pending, must_enroll, me}`: a pending MFA moves to the
 * code step (`POST /auth/mfa`), a required enrollment to TOTP setup. Enrollment does not complete sign-in
 * (SR-03): the code step follows, with a later code from the new authenticator. An existing limited session (for
 * example after a reload) resumes at the right step. SSO errors arrive as `?sso_error=<code>`; for
 * `mfa_required` after an SSO step-up the TOTP fallback (`POST /auth/reauth/totp`) is offered.
 *
 * With a default provider (`direct_provider`), `/login` continues to it at once; `/login/password` always shows every
 * sign-in method. The page stays put after an SSO error and after signing out, so it never loops through the provider.
 *
 * Public auth endpoints carry no CSRF token (the server checks Origin); after login the session's token
 * comes from `me.csrf_token`.
 */

const PUBLIC_OPTS = { csrf: 'none', authRedirect: false, reauth: false } as const;
const SESSION_OPTS = { authRedirect: false, reauth: false } as const;

type Step = 'credentials' | 'mfa' | 'enroll' | 'stepup-totp';

/** Shown on the code step right after enrollment: the code used to confirm cannot be reused. */
export const AFTER_ENROLL_INTRO =
  'Your authenticator is set up. To finish signing in, wait for it to show a new code and enter that code (or one of your recovery codes).';

function LocalLoginForm({
  client,
  onResult,
}: {
  client: ApiClient;
  onResult: (step: Step | 'done', me: Me) => void;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (values: LoginRequest) => {
    setPending(true);
    setError(null);
    try {
      const res = await client.call('post', '/api/v1/auth/login', {
        body: { email: values.email.trim(), password: values.password },
        ...PUBLIC_OPTS,
      });
      client.setCsrfToken(res.me.csrf_token);
      onResult(res.must_enroll ? 'enroll' : res.mfa_pending ? 'mfa' : 'done', res.me);
    } catch (e) {
      setError(e);
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
      aria-label="Sign in with email and password"
    >
      <Form.Item label="Email" name="email" rules={[{ required: true, message: 'Enter your email' }]}>
        <Input type="email" autoComplete="username" autoCapitalize="none" spellCheck={false} />
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

/** One code field (TOTP or recovery code) with a submit button; also used by setup and recovery. */
export function CodeForm({
  label,
  intro,
  onSubmit,
  onBack,
  backLabel = 'Use a different account',
}: {
  label: string;
  intro: string;
  onSubmit: (code: string) => Promise<void>;
  onBack?: () => void;
  backLabel?: string;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const codeInput = useRef<InputRef>(null);

  // Move focus to the code field when this step replaces the password form.
  useEffect(() => {
    codeInput.current?.focus();
  }, []);

  const submit = async (values: { code: string }) => {
    setPending(true);
    setError(null);
    try {
      await onSubmit(values.code.trim());
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Form<{ code: string }>
      layout="vertical"
      requiredMark={false}
      onFinish={(values) => {
        void submit(values);
      }}
      aria-label={label}
    >
      <p>{intro}</p>
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
      {onBack ? (
        <Button type="link" block onClick={onBack} disabled={pending} style={{ marginTop: 8 }}>
          {backLabel}
        </Button>
      ) : null}
    </Form>
  );
}

function SsoButtons({ providers, next }: { providers: readonly AuthProviderSummary[]; next: string }) {
  return (
    <nav aria-label="Single sign-on providers" style={{ display: 'grid', gap: 8 }}>
      {providers.map((p) => (
        <Button key={p.slug} block href={oidcStartUrl(p.slug, 'login', next)}>
          Sign in with {p.display_name}
        </Button>
      ))}
    </nav>
  );
}

export interface LoginFormsProps {
  config: AuthConfig;
  next: string;
  /** Called once the session is complete; `target` overrides `next` (step-up fallback). */
  onSignedIn: (target?: string) => void;
  client?: ApiClient;
  /** Step to start at (resuming a limited session or an SSO `mfa_required` fallback). */
  initialStep?: Step;
  ssoError?: string | undefined;
}

export function LoginForms({
  config,
  next,
  onSignedIn,
  client = defaultClient,
  initialStep = 'credentials',
  ssoError,
}: LoginFormsProps) {
  const [step, setStep] = useState<Step>(initialStep);
  const [justEnrolled, setJustEnrolled] = useState(false);
  const providers = config.providers;
  const back = () => {
    // Abandon the limited session server-side; ignore failures (it expires anyway).
    void client.call('post', '/api/v1/auth/logout', SESSION_OPTS).catch(() => undefined);
    client.clearSession();
    setStep('credentials');
  };

  if (step === 'mfa') {
    return (
      <CodeForm
        label="Two-factor authentication"
        intro={
          justEnrolled
            ? AFTER_ENROLL_INTRO
            : 'Enter the code from your authenticator app, or one of your recovery codes.'
        }
        onSubmit={async (code) => {
          const me = await client.call('post', '/api/v1/auth/mfa', { body: { code }, ...SESSION_OPTS });
          client.setCsrfToken(me.csrf_token);
          onSignedIn();
        }}
        onBack={back}
      />
    );
  }
  if (step === 'enroll') {
    return (
      <>
        <Alert
          type="info"
          showIcon
          title="Set up two-factor authentication"
          description="Your account requires an authenticator app before you can continue."
          style={{ marginBottom: 16 }}
        />
        <TotpEnrollment
          client={client}
          limited
          onDone={() => {
            setJustEnrolled(true);
            setStep('mfa');
          }}
          onCancel={back}
        />
      </>
    );
  }
  if (step === 'stepup-totp') {
    return (
      <CodeForm
        label="Confirm with authenticator code"
        intro={ssoErrorMessage('mfa_required')}
        onSubmit={async (code) => {
          await client.call('post', '/api/v1/auth/reauth/totp', { body: { code }, ...SESSION_OPTS });
          client.clearSession();
          onSignedIn(takeStepUpReturn());
        }}
        onBack={() => {
          onSignedIn(takeStepUpReturn());
        }}
        backLabel="Skip and return"
      />
    );
  }

  const error = ssoError ? (
    <Alert type="error" showIcon title={ssoErrorMessage(ssoError)} style={{ marginBottom: 16 }} />
  ) : null;

  if (!config.local_login && providers.length === 0) {
    return (
      <>
        {error}
        <Alert
          type="warning"
          showIcon
          title="No sign-in method is enabled"
          description={
            <>
              An administrator can restore access with <code className="hp-mono">hallpass admin recover</code>{' '}
              on the server.
            </>
          }
        />
      </>
    );
  }
  return (
    <>
      {error}
      {config.bootstrap_required ? (
        <Alert
          type="info"
          showIcon
          title="HallPass is not set up yet"
          description={
            <>
              Run <code className="hp-mono">hallpass admin bootstrap</code> on the server and open the setup
              link it prints.
            </>
          }
          style={{ marginBottom: 16 }}
        />
      ) : null}
      {config.local_login ? (
        <LocalLoginForm
          client={client}
          onResult={(nextStep) => {
            if (nextStep === 'done') {
              onSignedIn();
            } else {
              setStep(nextStep);
            }
          }}
        />
      ) : null}
      {config.local_login && providers.length > 0 ? <Divider plain>or</Divider> : null}
      {providers.length > 0 ? <SsoButtons providers={providers} next={next} /> : null}
    </>
  );
}

/** Where to resume for an existing session (`null`: none, show the credentials form). */
export function resumeStep(me: Me | undefined, ssoError: string | undefined): Step | 'done' | null {
  if (!me) {
    return null;
  }
  if (ssoError === 'mfa_required' && !me.session.limited && me.session.method === 'oidc') {
    return me.operator.mfa_enrolled ? 'stepup-totp' : null;
  }
  if (me.session.limited) {
    return me.session.needs_enroll ? 'enroll' : 'mfa';
  }
  return ssoError ? null : 'done';
}

/** Where the browser is sent for the default provider (overridable in tests). */
const defaultRedirect = (url: string) => {
  window.location.replace(url);
};

/** Shown while the browser continues to the default provider, with a way out if the redirect stalls. */
function DirectSignIn({
  provider,
  next,
  localLogin,
  redirect,
}: {
  provider: AuthProviderSummary;
  next: string;
  localLogin: boolean;
  redirect: (url: string) => void;
}) {
  const href = oidcStartUrl(provider.slug, 'login', next);
  useEffect(() => {
    redirect(href);
  }, [href, redirect]);
  const fallback = next === '/' ? '/login/password' : `/login/password?next=${encodeURIComponent(next)}`;
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <p role="status" style={{ margin: 0 }}>
        Continuing to {provider.display_name}…
      </p>
      <Button block href={href}>
        Continue with {provider.display_name}
      </Button>
      <Button type="link" block href={fallback}>
        {localLogin ? 'Sign in with email and password' : 'Other sign-in options'}
      </Button>
    </div>
  );
}

export function LoginPage({
  next,
  ssoError,
  onSignedIn,
  client = defaultClient,
  direct = false,
  redirect = defaultRedirect,
}: {
  next: string;
  ssoError?: string | undefined;
  onSignedIn: (target?: string) => void;
  client?: ApiClient;
  /** Continue straight to the default SSO provider when one is set (`/login`; not `/login/password`). */
  direct?: boolean;
  redirect?: (url: string) => void;
}) {
  const config = useQuery(authConfigQueryOptions());
  // An existing session (limited, or a full one after an SSO step-up fallback) decides the first step.
  const session = useQuery({
    queryKey: ['login-session'],
    queryFn: ({ signal }) => client.getMe({ signal, authRedirect: false }),
    retry: false,
    staleTime: 0,
    gcTime: 0,
  });
  const resume = session.isSuccess ? resumeStep(session.data, ssoError) : null;
  const [signedOut] = useState(wasSignedOut);
  const directProvider =
    direct &&
    config.isSuccess &&
    !config.data.bootstrap_required &&
    !ssoError &&
    !signedOut &&
    resume === null
      ? config.data.providers.find((p) => p.slug === config.data.direct_provider)
      : undefined;

  useEffect(() => {
    if (resume === 'done') {
      onSignedIn();
    }
  }, [resume, onSignedIn]);

  return (
    <AuthLayout title="Sign in to HallPass">
      {config.isPending || session.isPending ? (
        <LoadingState label="Loading sign-in options…" />
      ) : config.isError ? (
        <ErrorState
          error={config.error}
          title="Sign-in options unavailable"
          onRetry={() => {
            void config.refetch();
          }}
        />
      ) : resume === 'done' ? (
        <LoadingState label="Signing in…" />
      ) : directProvider ? (
        <DirectSignIn
          provider={directProvider}
          next={next}
          localLogin={config.data.local_login}
          redirect={redirect}
        />
      ) : (
        <>
          {direct && signedOut && config.data.direct_provider && !ssoError && resume === null ? (
            <Alert type="info" showIcon title="You are signed out." style={{ marginBottom: 16 }} />
          ) : null}
          <LoginForms
            config={config.data}
            next={next}
            onSignedIn={onSignedIn}
            client={client}
            ssoError={ssoError}
            {...(resume ? { initialStep: resume } : {})}
          />
        </>
      )}
    </AuthLayout>
  );
}
