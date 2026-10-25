import { PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Form, Input, Select, Space, Tag } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import {
  authSettingsQueryOptions,
  oidcMappingsQueryOptions,
  oidcProvidersQueryOptions,
  oidcTestLoginQueryOptions,
} from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { OIDCProvider, OIDCTestResult } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { CopyField } from '../../ds/CopyField';
import { DataTable } from '../../ds/DataTable';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { EmptyState, ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { revealControls } from '../../ds/untrusted';
import { formatDateTime } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { oidcStartUrl } from '../auth/sso';
import { ProviderFormDrawer } from './ProviderForm';
import { ResponsiveTable } from '../../ds/DataTable';

const OPERATOR_ROLES = ['administrator', 'approver', 'auditor', 'viewer'] as const;

/**
 * Settings → Authentication (HP-UI-005, HP-OIDC-*, HP-AUTH-015): login methods (SSO-only enforcement),
 * OIDC providers (write-only client secret, copyable redirect URI), group mappings, and the test-login
 * workflow with its claim/mapping preview.
 */
export function AuthSettingsPage({
  testLoginProviderId,
  onClearTestLogin,
  navigate = (url: string) => {
    window.location.assign(url);
  },
}: {
  testLoginProviderId?: string | undefined;
  onClearTestLogin?: () => void;
  navigate?: (url: string) => void;
}) {
  const { can, loading } = usePermissions();
  if (loading) {
    return <LoadingState />;
  }
  if (!can('auth.settings')) {
    return (
      <>
        <PageHeader title="Authentication" />
        <PermissionDenied />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Authentication"
        description="Sign-in methods, single sign-on providers, group mappings and SSO test logins."
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {testLoginProviderId ? (
          <TestLoginPreview providerId={testLoginProviderId} onClose={onClearTestLogin} />
        ) : null}
        <LocalLoginCard />
        <DefaultSignInCard />
        <ProvidersCard navigate={navigate} />
        <Card title="Not configurable here" size="small">
          <p style={{ margin: 0 }}>
            Password and MFA policy, session lifetimes and discovery checks are set in the{' '}
            <code className="hp-mono">auth</code> section of the server configuration file (
            <code className="hp-mono">hallpass.yaml</code>) and take effect after a restart.
          </p>
        </Card>
      </Space>
    </>
  );
}

function LocalLoginCard() {
  const queryClient = useQueryClient();
  const settings = useQuery(authSettingsQueryOptions());
  const set = (disabled: boolean) =>
    api.call('put', '/api/v1/settings/auth', { body: { local_login_disabled: disabled } });
  const onSuccess = () => {
    void queryClient.invalidateQueries({ queryKey: qk.authSettings });
    void queryClient.invalidateQueries({ queryKey: qk.authConfig });
  };
  return (
    <Card title="Password sign-in" size="small">
      {settings.isPending ? (
        <LoadingState />
      ) : settings.isError ? (
        <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />
      ) : settings.data.local_login_disabled ? (
        <Space orientation="vertical" style={{ width: '100%' }}>
          <StatusBadge tone="warning">Disabled: single sign-on only</StatusBadge>
          <p style={{ margin: 0 }}>
            Operators can sign in only through an enabled SSO provider. If every provider fails, use{' '}
            <code className="hp-mono">hallpass admin recover</code> on the server (break-glass, audited).
          </p>
          <ConfirmAction
            label="Re-enable password sign-in"
            title="Re-enable password sign-in"
            danger={false}
            description="Operators with a local password will be able to sign in with it again."
            confirmLabel="Re-enable"
            onConfirm={() => set(false)}
            onSuccess={onSuccess}
          />
        </Space>
      ) : (
        <Space orientation="vertical" style={{ width: '100%' }}>
          <StatusBadge tone="success">Enabled</StatusBadge>
          <ConfirmAction
            label="Disable password sign-in (SSO only)"
            title="Enforce single sign-on"
            typedConfirmation="SSO ONLY"
            confirmLabel="Disable password sign-in"
            description={
              <Alert
                type="warning"
                showIcon
                title="Every operator will have to sign in through SSO"
                description={
                  <>
                    Password sign-in stops immediately for everyone, including administrators. The server
                    refuses this until an administrator completed an SSO test login on an enabled provider and
                    at least one administrator can sign in with SSO. Recovery without SSO requires{' '}
                    <code className="hp-mono">hallpass admin recover</code> on the server.
                  </>
                }
              />
            }
            onConfirm={() => set(true)}
            onSuccess={onSuccess}
          />
        </Space>
      )}
    </Card>
  );
}

function DefaultSignInCard() {
  const queryClient = useQueryClient();
  const settings = useQuery(authSettingsQueryOptions());
  const providers = useQuery(oidcProvidersQueryOptions());
  const [choice, setChoice] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  if (settings.isPending || providers.isPending) {
    return (
      <Card title="Default sign-in" size="small">
        <LoadingState />
      </Card>
    );
  }
  if (settings.isError || providers.isError) {
    return (
      <Card title="Default sign-in" size="small">
        <ErrorState
          error={settings.error ?? providers.error}
          onRetry={() => {
            void settings.refetch();
            void providers.refetch();
          }}
        />
      </Card>
    );
  }
  const current = settings.data.direct_provider ?? '';
  const value = choice ?? current;
  const enabled = providers.data.items.filter((p) => p.enabled);
  const save = async () => {
    setPending(true);
    setError(null);
    try {
      await api.call('put', '/api/v1/settings/auth', {
        body: { local_login_disabled: settings.data.local_login_disabled, direct_provider: value },
      });
      setChoice(null);
      void queryClient.invalidateQueries({ queryKey: qk.authSettings });
      void queryClient.invalidateQueries({ queryKey: qk.authConfig });
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };
  return (
    <Card title="Default sign-in" size="small">
      <Space orientation="vertical" style={{ width: '100%' }}>
        <p style={{ margin: 0 }}>
          Send the sign-in page straight to one SSO provider instead of showing the sign-in options. It still
          shows them after a failed SSO sign-in and right after signing out.
        </p>
        <Form layout="vertical" style={{ maxWidth: 'min(420px, 100%)' }}>
          <Form.Item label="Sign-in page" style={{ marginBottom: 8 }}>
            <Select
              aria-label="Sign-in page"
              value={value}
              onChange={(v: string) => {
                setChoice(v);
              }}
              options={[
                { value: '', label: 'Show the sign-in options' },
                ...enabled.map((p) => ({ value: p.slug, label: `Continue to ${p.display_name}` })),
              ]}
            />
          </Form.Item>
          <Button type="primary" onClick={() => void save()} loading={pending} disabled={value === current}>
            Save
          </Button>
        </Form>
        {error !== null ? <Alert type="error" showIcon title={errorMessage(error)} /> : null}
        {current !== '' ? (
          <CopyField
            label={
              settings.data.local_login_disabled
                ? 'Every sign-in option'
                : 'Email and password sign-in (fallback)'
            }
            value={`${window.location.origin}/login/password`}
          />
        ) : null}
      </Space>
    </Card>
  );
}

function ProvidersCard({ navigate }: { navigate: (url: string) => void }) {
  const queryClient = useQueryClient();
  const providers = useQuery(oidcProvidersQueryOptions());
  const [editing, setEditing] = useState<OIDCProvider | null | undefined>(undefined);
  const [selected, setSelected] = useState<string | null>(null);
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: qk.oidcProviders });
    void queryClient.invalidateQueries({ queryKey: qk.authConfig });
  };
  const current = providers.data?.items.find((p) => p.id === selected);

  return (
    <Card
      title="Single sign-on providers"
      size="small"
      extra={
        <Button
          icon={<PlusOutlined />}
          onClick={() => {
            setEditing(null);
          }}
        >
          Add provider
        </Button>
      }
    >
      <DataTable<OIDCProvider>
        caption="SSO providers"
        rows={providers.data?.items}
        rowKey="id"
        loading={providers.isPending}
        error={providers.error}
        onRetry={() => void providers.refetch()}
        emptyTitle="No SSO providers"
        emptyDescription="Add an OpenID Connect provider to offer single sign-on."
        columns={[
          { key: 'display_name', title: 'Name', render: (_v, p) => p.display_name },
          { key: 'slug', title: 'Slug', render: (_v, p) => <code className="hp-mono">{p.slug}</code> },
          { key: 'issuer', title: 'Issuer', render: (_v, p) => <span className="hp-mono">{p.issuer}</span> },
          {
            key: 'enabled',
            title: 'Status',
            render: (_v, p) =>
              p.enabled ? (
                <StatusBadge tone="success">Enabled</StatusBadge>
              ) : (
                <StatusBadge tone="neutral">Disabled</StatusBadge>
              ),
          },
          {
            key: 'provisioning',
            title: 'Provisioning',
            render: (_v, p) => (p.provisioning === 'jit' ? 'Just-in-time' : 'Pre-provisioned'),
          },
          {
            key: 'secret',
            title: 'Client secret',
            render: (_v, p) => (p.has_client_secret ? 'Stored' : 'None'),
          },
          {
            key: 'test',
            title: 'Last successful test login',
            render: (_v, p) =>
              p.test_login_ok_at ? (
                formatDateTime(p.test_login_ok_at)
              ) : (
                <StatusBadge tone="warning">Never</StatusBadge>
              ),
          },
          {
            key: 'actions',
            title: <span className="hp-visually-hidden">Actions</span>,
            render: (_v, p) => (
              <Space>
                <Button
                  size="small"
                  onClick={() => {
                    setSelected(p.id === selected ? null : p.id);
                  }}
                >
                  {p.id === selected ? 'Hide details' : 'Details'}
                </Button>
                <Button
                  size="small"
                  onClick={() => {
                    setEditing(p);
                  }}
                >
                  Edit
                </Button>
              </Space>
            ),
          },
        ]}
      />
      {current ? (
        <ProviderDetail
          provider={current}
          navigate={navigate}
          onDeleted={() => {
            setSelected(null);
            refresh();
          }}
        />
      ) : null}
      <ProviderFormDrawer
        open={editing !== undefined}
        provider={editing ?? undefined}
        onClose={() => {
          setEditing(undefined);
        }}
        onSaved={(p) => {
          setEditing(undefined);
          setSelected(p.id);
          refresh();
        }}
      />
    </Card>
  );
}

function ProviderDetail({
  provider,
  navigate,
  onDeleted,
}: {
  provider: OIDCProvider;
  navigate: (url: string) => void;
  onDeleted: () => void;
}) {
  return (
    <section aria-label={`${provider.display_name} details`} style={{ marginTop: 16 }}>
      <h2 style={{ fontSize: 16 }}>{provider.display_name}</h2>
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {provider.redirect_uri ? (
          <CopyField label="Redirect URI (register at the provider)" value={provider.redirect_uri} />
        ) : null}
        <KeyValueGrid
          items={[
            {
              key: 'client',
              label: 'Client ID',
              value: <code className="hp-mono">{provider.client_id}</code>,
            },
            { key: 'scopes', label: 'Scopes', value: provider.scopes.join(' ') || '—' },
            {
              key: 'groups',
              label: 'Groups claim',
              value:
                provider.groups_claim === undefined || provider.groups_claim === ''
                  ? '—'
                  : provider.groups_claim,
            },
            {
              key: 'stepup',
              label: 'Step-up fallback',
              value: provider.stepup_fallback === 'local_totp' ? 'HallPass TOTP' : 'None',
            },
            {
              key: 'acr',
              label: 'Required ACR',
              value: provider.acr_values?.length ? provider.acr_values.join(', ') : '—',
            },
            { key: 'version', label: 'Version', value: provider.version },
          ]}
        />
        <Card size="small" title="Test login">
          <p>
            Signs you in at the provider in a fresh login and shows the claims and the roles HallPass would
            map, without creating a session. A successful test is required before SSO-only enforcement.
          </p>
          <Button
            onClick={() => {
              navigate(oidcStartUrl(provider.slug, 'test', '/settings/auth'));
            }}
          >
            Run test login
          </Button>
        </Card>
        <MappingsCard provider={provider} />
        <ConfirmAction
          label="Delete provider"
          title={`Delete ${provider.display_name}`}
          typedConfirmation={provider.slug}
          confirmLabel="Delete"
          description="Operators linked only through this provider can no longer sign in with SSO. The server refuses deletion if it would leave SSO-only enforcement without a working administrator path."
          onConfirm={() => api.call('delete', '/api/v1/oidc-providers/{id}', { path: { id: provider.id } })}
          onSuccess={onDeleted}
        />
      </Space>
    </section>
  );
}

interface MappingValues {
  group_value: string;
  target: 'role' | 'group';
  role?: string;
  group_id?: string;
}

function MappingsCard({ provider }: { provider: OIDCProvider }) {
  const queryClient = useQueryClient();
  const mappings = useQuery(oidcMappingsQueryOptions(provider.id));
  const [form] = Form.useForm<MappingValues>();
  const target = Form.useWatch('target', form);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const refresh = () => queryClient.invalidateQueries({ queryKey: qk.oidcMappings(provider.id) });

  const add = async (v: MappingValues) => {
    setPending(true);
    setError(null);
    try {
      await api.call('post', '/api/v1/oidc-providers/{id}/mappings', {
        path: { id: provider.id },
        body: {
          group_value: v.group_value.trim(),
          ...(v.target === 'role' ? { role: v.role ?? '' } : { group_id: (v.group_id ?? '').trim() }),
        },
      });
      form.resetFields();
      await refresh();
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Card size="small" title="Group mappings">
      <p>
        Values of the <code className="hp-mono">{provider.groups_claim ?? 'groups'}</code> claim map to an
        operator role or a HallPass operator group. SSO-mapped roles are managed by the provider at each
        login.
      </p>
      {mappings.isPending ? (
        <LoadingState />
      ) : mappings.isError ? (
        <ErrorState error={mappings.error} onRetry={() => void mappings.refetch()} />
      ) : mappings.data.items.length === 0 ? (
        <EmptyState title="No mappings" description="Without mappings, SSO operators receive no roles." />
      ) : (
        <ResponsiveTable
          size="small"
          pagination={false}
          rowKey="id"
          dataSource={mappings.data.items}
          columns={[
            {
              key: 'g',
              title: 'Claim value',
              render: (_v, m) => <code className="hp-mono">{m.group_value}</code>,
            },
            {
              key: 't',
              title: 'Maps to',
              render: (_v, m) => (m.role ? <Tag>role: {m.role}</Tag> : <Tag>group: {m.group_id}</Tag>),
            },
            {
              key: 'a',
              title: <span className="hp-visually-hidden">Actions</span>,
              render: (_v, m) => (
                <ConfirmAction
                  label="Remove"
                  title="Remove mapping"
                  buttonProps={{ size: 'small' }}
                  description={`Operators with "${m.group_value}" lose this ${m.role ? 'role' : 'group'} at their next SSO login.`}
                  onConfirm={() =>
                    api.call('delete', '/api/v1/oidc-providers/{id}/mappings/{mid}', {
                      path: { id: provider.id, mid: m.id },
                    })
                  }
                  onSuccess={() => void refresh()}
                />
              ),
            },
          ]}
        />
      )}
      <Form<MappingValues>
        form={form}
        layout="inline"
        initialValues={{ target: 'role', role: 'viewer' }}
        onFinish={(v) => void add(v)}
        aria-label="Add group mapping"
        style={{ marginTop: 12, rowGap: 8 }}
      >
        <Form.Item
          label="Claim value"
          name="group_value"
          rules={[{ required: true, message: 'Enter a value' }]}
        >
          <Input spellCheck={false} />
        </Form.Item>
        <Form.Item label="Maps to" name="target">
          <Select
            style={{ width: 160 }}
            options={[
              { value: 'role', label: 'Operator role' },
              { value: 'group', label: 'Operator group' },
            ]}
          />
        </Form.Item>
        {target === 'group' ? (
          <Form.Item
            label="Group ID"
            name="group_id"
            rules={[{ required: true, message: 'Enter a group ID' }]}
          >
            <Input spellCheck={false} />
          </Form.Item>
        ) : (
          <Form.Item label="Role" name="role" rules={[{ required: true }]}>
            <Select style={{ width: 160 }} options={OPERATOR_ROLES.map((r) => ({ value: r, label: r }))} />
          </Form.Item>
        )}
        <Form.Item>
          <Button htmlType="submit" loading={pending}>
            Add mapping
          </Button>
        </Form.Item>
      </Form>
      {error !== null ? (
        <Alert style={{ marginTop: 8 }} type="error" showIcon title={errorMessage(error)} />
      ) : null}
    </Card>
  );
}

/** Pretty JSON with hidden/bidi characters revealed. Claims come from the IdP; rendered as text only. */
export function claimsText(claims: unknown): string {
  return revealControls(JSON.stringify(claims, null, 2));
}

function TestLoginPreview({
  providerId,
  onClose,
}: {
  providerId: string;
  onClose?: (() => void) | undefined;
}) {
  const result = useQuery({ ...oidcTestLoginQueryOptions(providerId), retry: false });
  return (
    <Card
      title="SSO test login result"
      size="small"
      extra={
        onClose ? (
          <Button size="small" onClick={onClose}>
            Dismiss
          </Button>
        ) : undefined
      }
    >
      {result.isPending ? (
        <LoadingState label="Loading test-login preview…" />
      ) : result.isError ? (
        <ErrorState error={result.error} title="No test-login preview" />
      ) : (
        <TestLoginResultView result={result.data} />
      )}
    </Card>
  );
}

export function TestLoginResultView({ result }: { result: OIDCTestResult }) {
  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <Alert
        type="success"
        showIcon
        title="The provider authenticated you"
        description="No session was created. The preview below is kept for 10 minutes."
      />
      <KeyValueGrid
        items={[
          {
            key: 'linked',
            label: 'Linked operator',
            value: result.linked_operator_id ? (
              <code className="hp-mono">{result.linked_operator_id}</code>
            ) : (
              'Not linked'
            ),
          },
          {
            key: 'provision',
            label: 'Would provision',
            value: result.would_provision
              ? 'Yes'
              : `No${result.provision_reason ? ` (${result.provision_reason})` : ''}`,
          },
          { key: 'roles', label: 'Mapped roles', value: result.mapped_roles.join(', ') || 'None' },
          { key: 'groups', label: 'Mapped groups', value: result.mapped_groups.join(', ') || 'None' },
          { key: 'effective', label: 'Effective roles', value: result.effective_roles.join(', ') || 'None' },
        ]}
      />
      <div>
        <h3 style={{ fontSize: 14 }}>Claims (as received from the provider)</h3>
        {/* Scrollable content must be keyboard-reachable (WCAG 2.1.1, axe scrollable-region-focusable). */}
        {/* eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex */}
        <pre className="hp-mono hp-pre" tabIndex={0} aria-label="Claims JSON">
          {claimsText(result.claims)}
        </pre>
      </div>
    </Space>
  );
}
