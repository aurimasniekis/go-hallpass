import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Form, Input, Select, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { operatorProviderLinksQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Operator } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { applyFieldErrors } from '../../lib/formErrors';
import { CHAT_PROVIDERS, ProviderLinksTable } from './tables';

interface Values {
  provider: string;
  workspace: string;
  provider_user_id: string;
  display?: string;
}

/**
 * Administrator-side chat account links (HP-NTF-011). A direct link is audited; the self-service code flow
 * on the operator's own account page is preferred because it proves control of the chat account.
 */
export function OperatorChatLinks({ operator }: { operator: Operator }) {
  const links = useQuery(operatorProviderLinksQueryOptions(operator.id));
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const [form] = Form.useForm<Values>();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey: qk.operatorProviderLinks(operator.id) });

  const submit = async (values: Values) => {
    setPending(true);
    setError(null);
    try {
      await api.call('post', '/api/v1/operators/{id}/provider-links', {
        path: { id: operator.id },
        body: {
          provider: values.provider,
          workspace: values.workspace.trim(),
          provider_user_id: values.provider_user_id.trim(),
          ...(values.display?.trim() ? { display: values.display.trim() } : {}),
        },
      });
      form.resetFields();
      await refresh();
      void message.success('Chat account linked');
    } catch (e) {
      applyFieldErrors(form, e);
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <ProviderLinksTable
        caption={`Chat accounts of ${operator.display_name}`}
        rows={links.data?.items}
        loading={links.isPending}
        error={links.error}
        onRetry={() => void links.refetch()}
        action={(l) => (
          <ConfirmAction
            label="Unlink"
            title="Unlink chat account"
            description="Decisions from this chat account will be refused. This is audited."
            confirmLabel="Unlink"
            buttonProps={{ size: 'small' }}
            onConfirm={() =>
              api.call('delete', '/api/v1/operators/{id}/provider-links', {
                path: { id: operator.id },
                query: { provider: l.provider, workspace: l.workspace, user_id: l.provider_user_id },
              })
            }
            onSuccess={() => {
              void refresh();
            }}
          />
        )}
      />
      <Form<Values>
        form={form}
        layout="inline"
        requiredMark={false}
        initialValues={{ provider: 'slack' }}
        onFinish={(v) => void submit(v)}
        aria-label="Link chat account"
      >
        <Form.Item label="Provider" name="provider" rules={[{ required: true }]}>
          <Select
            aria-label="Provider"
            options={CHAT_PROVIDERS.map((p) => ({ ...p }))}
            style={{ width: 130 }}
          />
        </Form.Item>
        <Form.Item
          label="Workspace"
          name="workspace"
          tooltip="Slack team ID, or the Telegram bot/integration workspace identifier"
          rules={[{ required: true, message: 'Enter the workspace' }]}
        >
          <Input spellCheck={false} />
        </Form.Item>
        <Form.Item
          label="User ID"
          name="provider_user_id"
          rules={[{ required: true, message: 'Enter the user ID' }]}
        >
          <Input spellCheck={false} />
        </Form.Item>
        <Form.Item label="Display name" name="display">
          <Input />
        </Form.Item>
        <Form.Item>
          <Button htmlType="submit" loading={pending}>
            Link account
          </Button>
        </Form.Item>
      </Form>
      {error !== null ? <Alert type="error" showIcon title={errorMessage(error)} /> : null}
    </Space>
  );
}
