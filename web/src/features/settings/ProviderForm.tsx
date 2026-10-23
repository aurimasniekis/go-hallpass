import { Alert, Button, Checkbox, Collapse, Drawer, Form, Input, Radio, Space, Switch } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import type { OIDCProvider } from '../../api/types';
import { TagsInput } from '../../ds/TagsInput';
import { applyFieldErrors } from '../../lib/formErrors';
import { formToProviderInput, providerToForm, type ProviderFormValues } from './providerValues';

/** Create/edit drawer for an OIDC provider (HP-OIDC-*, HP-UI-005). */
export function ProviderFormDrawer({
  open,
  provider,
  onClose,
  onSaved,
}: {
  open: boolean;
  /** Undefined = create. */
  provider: OIDCProvider | undefined;
  onClose: () => void;
  onSaved: (p: OIDCProvider) => void;
}) {
  const [form] = Form.useForm<ProviderFormValues>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const provisioning = Form.useWatch('provisioning', form);
  const removeSecret = Form.useWatch('remove_secret', form);

  const submit = async (values: ProviderFormValues) => {
    setPending(true);
    setError(null);
    try {
      const saved = provider
        ? await api.call('patch', '/api/v1/oidc-providers/{id}', {
            path: { id: provider.id },
            body: formToProviderInput(values),
            ifMatch: provider.version,
          })
        : await api.call('post', '/api/v1/oidc-providers', { body: formToProviderInput(values) });
      // Never keep the typed secret in form state after the server accepted it.
      form.setFieldValue('client_secret', '');
      onSaved(saved);
    } catch (e) {
      applyFieldErrors(form, e);
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Drawer
      open={open}
      title={provider ? `Edit ${provider.display_name}` : 'Add SSO provider'}
      size="large"
      destroyOnHidden
      onClose={() => {
        if (!pending) {
          onClose();
        }
      }}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <Button onClick={onClose} disabled={pending}>
            Cancel
          </Button>
          <Button
            type="primary"
            loading={pending}
            onClick={() => {
              form.submit();
            }}
          >
            {provider ? 'Save changes' : 'Create provider'}
          </Button>
        </div>
      }
    >
      <Form<ProviderFormValues>
        form={form}
        layout="vertical"
        requiredMark="optional"
        initialValues={providerToForm(provider)}
        onFinish={(v) => void submit(v)}
        aria-label="SSO provider settings"
      >
        <Form.Item
          label="Slug"
          name="slug"
          extra="Used in URLs (/auth/oidc/<slug>/…). Lowercase letters, digits and dashes."
          rules={[{ required: true, message: 'Enter a slug' }]}
        >
          <Input spellCheck={false} autoCapitalize="none" />
        </Form.Item>
        <Form.Item
          label="Display name"
          name="display_name"
          rules={[{ required: true, message: 'Enter a name' }]}
        >
          <Input />
        </Form.Item>
        <Form.Item
          label="Issuer URL"
          name="issuer"
          extra="Discovery is fetched from <issuer>/.well-known/openid-configuration."
          rules={[{ required: true, message: 'Enter the issuer URL' }]}
        >
          <Input type="url" spellCheck={false} />
        </Form.Item>
        <Form.Item
          label="Client ID"
          name="client_id"
          rules={[{ required: true, message: 'Enter the client ID' }]}
        >
          <Input spellCheck={false} />
        </Form.Item>
        <Form.Item
          label="Client secret"
          name="client_secret"
          extra={
            provider?.has_client_secret
              ? 'A secret is stored (write-only; it is never shown). Leave blank to keep it.'
              : 'Leave blank for public clients (PKCE only).'
          }
        >
          <Input.Password autoComplete="new-password" disabled={removeSecret === true} />
        </Form.Item>
        {provider?.has_client_secret ? (
          <Form.Item name="remove_secret" valuePropName="checked">
            <Checkbox>Remove the stored client secret</Checkbox>
          </Form.Item>
        ) : null}
        <Form.Item label="Scopes" name="scopes">
          <TagsInput aria-label="Scopes" />
        </Form.Item>
        <Form.Item
          label="Groups claim"
          name="groups_claim"
          extra="Claim holding group values for role mappings."
        >
          <Input spellCheck={false} />
        </Form.Item>
        <Form.Item label="Provisioning" name="provisioning">
          <Radio.Group
            options={[
              { value: 'preprovisioned', label: 'Pre-provisioned (link existing operators only)' },
              { value: 'jit', label: 'Just-in-time (create operators on first login)' },
            ]}
          />
        </Form.Item>
        {provisioning === 'jit' ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            title="Just-in-time provisioning creates operators from IdP claims"
            description="Restrict it with at least one rule below; new operators get only mapped roles."
          />
        ) : null}
        {provisioning === 'jit' ? (
          <>
            <Form.Item
              label="Allowed email domains"
              name="jit_email_domains"
              extra="Requires email_verified=true."
            >
              <TagsInput aria-label="Allowed email domains" />
            </Form.Item>
            <Form.Item label="Allowed tenants (tid)" name="jit_tenants">
              <TagsInput aria-label="Allowed tenants" />
            </Form.Item>
            <Form.Item label="Allowed hosted domains (hd)" name="jit_hosted_domains">
              <TagsInput aria-label="Allowed hosted domains" />
            </Form.Item>
            <Form.Item label="Required groups" name="jit_groups">
              <TagsInput aria-label="Required groups" />
            </Form.Item>
          </>
        ) : null}
        <Form.Item
          label="Step-up fallback"
          name="stepup_fallback"
          extra="When the IdP cannot prove a fresh login (no auth_time), allow confirming with the operator's Hallpass TOTP."
        >
          <Radio.Group
            options={[
              { value: 'none', label: 'None (refuse)' },
              { value: 'local_totp', label: 'Hallpass TOTP' },
            ]}
          />
        </Form.Item>
        <Form.Item label="Required ACR values" name="acr_values">
          <TagsInput aria-label="Required ACR values" />
        </Form.Item>
        <Collapse
          size="small"
          style={{ marginBottom: 16 }}
          items={[
            {
              key: 'advanced',
              label: 'Advanced network settings',
              children: (
                <>
                  <Form.Item
                    name="allow_private_network"
                    valuePropName="checked"
                    extra="Allows provider endpoints on private or loopback addresses (SSRF risk)."
                  >
                    <Checkbox>Allow private network endpoints</Checkbox>
                  </Form.Item>
                  <Form.Item
                    name="allow_cross_origin_endpoints"
                    valuePropName="checked"
                    extra="Allows token/JWKS endpoints on a different origin than the issuer."
                  >
                    <Checkbox>Allow cross-origin endpoints</Checkbox>
                  </Form.Item>
                  <Form.Item label="CA bundle (PEM)" name="ca_bundle_pem">
                    <Input.TextArea rows={4} spellCheck={false} className="hp-mono" />
                  </Form.Item>
                </>
              ),
            },
          ]}
        />
        <Space orientation="vertical">
          <Form.Item name="end_session_enabled" valuePropName="checked" noStyle>
            <Checkbox>Offer RP-initiated logout at the provider after sign-out</Checkbox>
          </Form.Item>
          <Form.Item label="Enabled" name="enabled" valuePropName="checked" style={{ marginTop: 16 }}>
            <Switch />
          </Form.Item>
        </Space>
        {error !== null ? <Alert type="error" showIcon title={errorMessage(error)} /> : null}
      </Form>
    </Drawer>
  );
}
