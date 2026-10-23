import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Form, Input, Select, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { oidcProvidersQueryOptions, operatorIdentitiesQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Operator } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { applyFieldErrors } from '../../lib/formErrors';
import { usePermissions } from '../../lib/usePermissions';
import { shareableLink } from './roles';
import { IdentitiesTable } from './tables';
import { useOneTimeSecret } from './useOneTimeSecret';

interface LinkValues {
  provider_id: string;
  subject: string;
}

/** SSO identities of an operator: list, direct link (provider + subject), unlink and link invitations. */
export function OperatorIdentities({ operator }: { operator: Operator }) {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const identities = useQuery(operatorIdentitiesQueryOptions(operator.id));
  const providers = useQuery({ ...oidcProvidersQueryOptions(), enabled: can('auth.settings') });
  const providerOptions = (providers.data?.items ?? []).map((p) => ({
    value: p.id,
    label: `${p.display_name} (${p.slug})`,
  }));
  const [form] = Form.useForm<LinkValues>();
  const [inviteProvider, setInviteProvider] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState<'link' | 'invite' | null>(null);
  const [error, setError] = useState<unknown>(null);
  const secret = useOneTimeSecret();

  const refresh = () => queryClient.invalidateQueries({ queryKey: qk.operatorIdentities(operator.id) });

  const link = async (values: LinkValues) => {
    setPending('link');
    setError(null);
    try {
      await api.call('post', '/api/v1/operators/{id}/identities', {
        path: { id: operator.id },
        body: { provider_id: values.provider_id.trim(), subject: values.subject.trim() },
      });
      form.resetFields();
      await refresh();
      void message.success('Identity linked');
    } catch (e) {
      applyFieldErrors(form, e);
      setError(e);
    } finally {
      setPending(null);
    }
  };

  const invite = async () => {
    if (!inviteProvider) {
      return;
    }
    setPending('invite');
    setError(null);
    try {
      const res = await api.call('post', '/api/v1/operators/{id}/link-invite', {
        path: { id: operator.id },
        body: { provider_id: inviteProvider.trim() },
      });
      secret.show({
        title: 'SSO link invitation',
        label: 'Link invitation',
        description: `Send this link to ${operator.display_name}. Opening it signs in at the identity provider and links that identity to this account. Single use.`,
        values: [shareableLink(res.url, res.token)],
      });
    } catch (e) {
      setError(e);
    } finally {
      setPending(null);
    }
  };

  const providerField = (ariaLabel: string, value?: string, onChange?: (v: string) => void) =>
    can('auth.settings') ? (
      <Select
        aria-label={ariaLabel}
        options={providerOptions}
        loading={providers.isPending}
        placeholder="Select a provider"
        style={{ minWidth: 240 }}
        {...(onChange ? { value, onChange } : {})}
      />
    ) : (
      <Input
        aria-label={ariaLabel}
        placeholder="Provider ID"
        spellCheck={false}
        {...(onChange
          ? {
              value: value ?? '',
              onChange: (e) => {
                onChange(e.target.value);
              },
            }
          : {})}
      />
    );

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <IdentitiesTable
        caption={`SSO identities of ${operator.display_name}`}
        rows={identities.data?.items}
        loading={identities.isPending}
        error={identities.error}
        onRetry={() => void identities.refetch()}
        action={(i) => (
          <ConfirmAction
            label="Unlink"
            title="Unlink SSO identity"
            description="The operator can no longer sign in with this identity. This is audited."
            confirmLabel="Unlink"
            buttonProps={{ size: 'small' }}
            onConfirm={() =>
              api.call('delete', '/api/v1/operators/{id}/identities', {
                path: { id: operator.id },
                query: { issuer: i.issuer, subject: i.subject },
              })
            }
            onSuccess={() => {
              void refresh();
            }}
          />
        )}
      />
      <Form<LinkValues>
        form={form}
        layout="inline"
        requiredMark={false}
        onFinish={(v) => void link(v)}
        aria-label="Link SSO identity"
      >
        <Form.Item
          label="Provider"
          name="provider_id"
          rules={[{ required: true, message: 'Select a provider' }]}
        >
          {providerField('Provider')}
        </Form.Item>
        <Form.Item
          label="Subject"
          name="subject"
          rules={[{ required: true, message: 'Enter the subject (sub claim)' }]}
        >
          <Input spellCheck={false} placeholder="sub claim" />
        </Form.Item>
        <Form.Item>
          <Button htmlType="submit" loading={pending === 'link'}>
            Link identity
          </Button>
        </Form.Item>
      </Form>
      <Space wrap>
        <span>Or send a link invitation:</span>
        {providerField('Provider for link invitation', inviteProvider, setInviteProvider)}
        <Button disabled={!inviteProvider} loading={pending === 'invite'} onClick={() => void invite()}>
          Create link invitation
        </Button>
      </Space>
      {error !== null ? <Alert type="error" showIcon title={errorMessage(error)} /> : null}
      {secret.dialog}
    </Space>
  );
}
