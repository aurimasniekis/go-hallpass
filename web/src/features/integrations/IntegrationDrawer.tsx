import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Checkbox, Drawer, Form, Input, Radio, Space } from 'antd';
import { useEffect, useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { qk } from '../../api/queryKeys';
import type { Integration, IntegrationProvider } from '../../api/types';
import { TagsInput } from '../../ds/TagsInput';
import { applyFieldErrors } from '../../lib/formErrors';
import {
  formToIntegrationBody,
  integrationToForm,
  newIntegrationForm,
  SECRET_NAMES,
  type IntegrationFormValues,
} from './integrationForm';

/**
 * Create or edit a Slack/Telegram integration. Secrets are write-only: inputs start empty, a blank input
 * keeps the stored value, and typed values are cleared with the form once the drawer closes.
 */
export function IntegrationDrawer({
  open,
  integration,
  onClose,
}: {
  open: boolean;
  integration: Integration | undefined;
  onClose: () => void;
}) {
  const [form] = Form.useForm<IntegrationFormValues>();
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [apiError, setApiError] = useState<unknown>(null);
  const watched = Form.useWatch('provider', form) as IntegrationProvider | undefined;
  const provider: IntegrationProvider = watched ?? integration?.provider ?? 'slack';

  useEffect(() => {
    if (open) {
      form.resetFields();
      form.setFieldsValue(integration ? integrationToForm(integration) : newIntegrationForm());
    }
  }, [open, integration, form]);

  const close = () => {
    // Drop any typed secrets from memory.
    form.resetFields();
    setErrors([]);
    setApiError(null);
    onClose();
  };

  const submit = async () => {
    const values = { ...newIntegrationForm(), ...form.getFieldsValue(true) } as IntegrationFormValues;
    const { body, errors: problems } = formToIntegrationBody(values, integration ? 'update' : 'create');
    setErrors(problems);
    setApiError(null);
    if (!body) {
      return;
    }
    setPending(true);
    try {
      if (integration) {
        await api.call('patch', '/api/v1/integrations/{id}', {
          path: { id: integration.id },
          body,
          ifMatch: integration.version,
        });
      } else {
        await api.call('post', '/api/v1/integrations', { body });
      }
      await queryClient.invalidateQueries({ queryKey: qk.integrations });
      close();
    } catch (e) {
      applyFieldErrors(form, e);
      setApiError(e);
    } finally {
      setPending(false);
    }
  };

  const stored = new Set(integration?.secrets_set ?? []);

  return (
    <Drawer
      open={open}
      onClose={() => {
        if (!pending) {
          close();
        }
      }}
      title={integration ? `Edit integration “${integration.name}”` : 'New chat integration'}
      size="large"
      destroyOnHidden
      mask={{ closable: !pending }}
      footer={
        <Space style={{ justifyContent: 'flex-end', width: '100%' }}>
          <Button onClick={close} disabled={pending}>
            Cancel
          </Button>
          <Button type="primary" loading={pending} onClick={() => void submit()}>
            {integration ? 'Save integration' : 'Create integration'}
          </Button>
        </Space>
      }
    >
      <Form<IntegrationFormValues>
        form={form}
        layout="vertical"
        requiredMark={false}
        aria-label="Chat integration"
      >
        <Form.Item label="Provider" name="provider">
          <Radio.Group
            disabled={integration !== undefined}
            optionType="button"
            options={[
              { value: 'slack', label: 'Slack' },
              { value: 'telegram', label: 'Telegram' },
            ]}
          />
        </Form.Item>
        <Form.Item label="Name" name="name" rules={[{ required: true, message: 'Enter a name' }]}>
          <Input maxLength={64} />
        </Form.Item>
        {provider === 'slack' ? (
          <>
            <Form.Item
              label="Workspace (team) ID"
              name="team_id"
              extra="Slack workspace ID, e.g. T0123ABCD. Callbacks from other workspaces are rejected."
              rules={[{ required: true, message: 'Enter the Slack team ID' }]}
            >
              <Input maxLength={32} spellCheck={false} />
            </Form.Item>
            <Form.Item label="Slash command" name="command" extra="Defaults to /hallpass.">
              <Input placeholder="/hallpass" spellCheck={false} />
            </Form.Item>
          </>
        ) : (
          <>
            <Form.Item
              label="Bot username"
              name="bot_username"
              extra="Shown in link instructions, e.g. hallpass_bot."
            >
              <Input spellCheck={false} />
            </Form.Item>
            <Form.Item
              label="Additional allowed chat IDs"
              name="allowed_chat_ids"
              extra="Group chats (negative IDs) besides route destinations that may interact with the bot. Private chats are always accepted for linking."
            >
              <TagsInput aria-label="Additional allowed chat IDs" placeholder="-1001234567890" />
            </Form.Item>
          </>
        )}
        <fieldset style={{ border: 0, padding: 0, margin: '0 0 8px' }}>
          <legend style={{ fontWeight: 600, fontSize: 14, marginBottom: 8 }}>Secrets (write-only)</legend>
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 12 }}
            title="Secrets are encrypted at rest and never shown again."
            description={
              integration
                ? 'Leave a field empty to keep the stored value. Treat these like credentials: anyone holding them can forge approval callbacks.'
                : 'Treat these like credentials: anyone holding them can forge approval callbacks.'
            }
          />
          {SECRET_NAMES[provider].map((s) => (
            <Form.Item
              key={s.name}
              label={`${s.label}${stored.has(s.name) ? ' (stored)' : ''}`}
              name={['secrets', s.name]}
              extra={
                stored.has(s.name) ? `${s.help} A value is stored; type a new one to replace it.` : s.help
              }
            >
              <Input.Password autoComplete="off" spellCheck={false} visibilityToggle={false} />
            </Form.Item>
          ))}
        </fieldset>
        <Form.Item name="enabled" valuePropName="checked">
          <Checkbox>Enabled</Checkbox>
        </Form.Item>
        {errors.length || apiError !== null ? (
          <Alert
            type="error"
            showIcon
            role="alert"
            title={apiError !== null ? 'The server rejected the change' : 'Fix these problems first'}
            description={
              <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                {apiError !== null ? <li>{errorMessage(apiError)}</li> : null}
                {errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            }
          />
        ) : null}
      </Form>
    </Drawer>
  );
}
