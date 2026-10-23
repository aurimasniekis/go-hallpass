import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Checkbox, Drawer, Form, Input, Radio, Space } from 'antd';
import { useEffect, useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { qk } from '../../api/queryKeys';
import type { ApproverRule, PolicyRule } from '../../api/types';
import { DurationInput } from '../../ds/DurationInput';
import { applyFieldErrors } from '../../lib/formErrors';
import { newIdempotencyKey } from '../../lib/idempotency';
import {
  approverToForm,
  formToApproverBody,
  formToRuleBody,
  LEVEL_LABEL,
  newApproverForm,
  newRuleForm,
  ruleToForm,
  type ApproverFormValues,
  type RuleFormValues,
  type RuleLevel,
} from './ruleForm';
import { SelectorEditor } from './selectors/SelectorEditor';

function FormProblems({ errors, apiError }: { errors: string[]; apiError: unknown }) {
  if (errors.length === 0 && apiError === null) {
    return null;
  }
  return (
    <Alert
      type="error"
      showIcon
      role="alert"
      style={{ marginBottom: 16 }}
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
  );
}

function useSubmitState() {
  const [pending, setPending] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [apiError, setApiError] = useState<unknown>(null);
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);
  const reset = () => {
    setErrors([]);
    setApiError(null);
    setIdempotencyKey(newIdempotencyKey());
  };
  return { pending, setPending, errors, setErrors, apiError, setApiError, idempotencyKey, reset };
}

/** Create or edit an access rule (docs/PLAN.md §9.1). `rule` undefined = create. */
export function RuleDrawer({
  open,
  rule,
  onClose,
}: {
  open: boolean;
  rule: PolicyRule | undefined;
  onClose: () => void;
}) {
  const [form] = Form.useForm<RuleFormValues>();
  const queryClient = useQueryClient();
  const state = useSubmitState();
  const effect = Form.useWatch('effect', form);
  const level = Form.useWatch('level', form);

  useEffect(() => {
    if (open) {
      form.setFieldsValue(rule ? ruleToForm(rule) : newRuleForm());
    }
  }, [open, rule, form]);

  const close = () => {
    // Fresh errors and a fresh Idempotency-Key for the next opening.
    state.reset();
    onClose();
  };

  const submit = async () => {
    const values = { ...newRuleForm(), ...form.getFieldsValue(true) } as RuleFormValues;
    const { body, errors } = formToRuleBody(values);
    state.setErrors(errors);
    state.setApiError(null);
    if (!body) {
      return;
    }
    state.setPending(true);
    try {
      if (rule?.id) {
        await api.call('patch', '/api/v1/policy/rules/{id}', {
          path: { id: rule.id },
          body,
          ...(rule.version !== undefined ? { ifMatch: rule.version } : {}),
        });
      } else {
        await api.call('post', '/api/v1/policy/rules', { body, idempotencyKey: state.idempotencyKey });
      }
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.policy }),
        queryClient.invalidateQueries({ queryKey: qk.effectiveAccess }),
      ]);
      close();
    } catch (e) {
      applyFieldErrors(form, e);
      state.setApiError(e);
    } finally {
      state.setPending(false);
    }
  };

  return (
    <Drawer
      open={open}
      onClose={() => {
        if (!state.pending) {
          close();
        }
      }}
      title={rule ? `Edit rule “${rule.name}”` : 'New access rule'}
      size="large"
      destroyOnHidden
      mask={{ closable: !state.pending }}
      footer={
        <Space style={{ justifyContent: 'flex-end', width: '100%' }}>
          <Button onClick={close} disabled={state.pending}>
            Cancel
          </Button>
          <Button type="primary" loading={state.pending} onClick={() => void submit()}>
            {rule ? 'Save rule' : 'Create rule'}
          </Button>
        </Space>
      }
    >
      <Form<RuleFormValues> form={form} layout="vertical" requiredMark={false} aria-label="Access rule">
        <Form.Item label="Name" name="name" rules={[{ required: true, message: 'Enter a name' }]}>
          <Input maxLength={128} />
        </Form.Item>
        <Form.Item label="Description" name="description">
          <Input.TextArea maxLength={2000} autoSize={{ minRows: 1, maxRows: 4 }} />
        </Form.Item>
        <Form.Item label="Effect" name="effect">
          <Radio.Group
            options={[
              { value: 'allow', label: 'Allow' },
              { value: 'deny', label: 'Deny (always wins)' },
            ]}
            optionType="button"
          />
        </Form.Item>
        {effect !== 'deny' ? (
          <>
            <Form.Item
              label="Level"
              name="level"
              extra="Visible: listed to the agent. Requestable: the agent may request access. Auto-approve: requests up to the auto-approval limit are approved without an operator."
            >
              <Radio.Group
                options={(Object.keys(LEVEL_LABEL) as RuleLevel[]).map((l) => ({
                  value: l,
                  label: LEVEL_LABEL[l],
                }))}
                optionType="button"
              />
            </Form.Item>
            <Form.Item
              label="Maximum duration"
              name="max_duration"
              extra="Leave empty to use the role's maximum."
            >
              <DurationInput aria-label="Maximum duration" minSeconds={60} />
            </Form.Item>
            {level === 'auto_approve' ? (
              <Form.Item
                label="Auto-approval limit"
                name="auto_max_duration"
                extra="Requests up to this duration are approved automatically. Must not exceed the maximum duration."
              >
                <DurationInput aria-label="Auto-approval limit" minSeconds={60} />
              </Form.Item>
            ) : null}
            <Form.Item name="require_reason" valuePropName="checked">
              <Checkbox>Require the agent to give a reason</Checkbox>
            </Form.Item>
          </>
        ) : (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
            title="Deny rules take no level or durations; a matching deny overrides every allow."
          />
        )}
        <Form.Item name="subjects" noStyle>
          <SelectorEditor kind="subject" legend="Agents (subjects)" />
        </Form.Item>
        <Form.Item name="targets" noStyle>
          <SelectorEditor kind="target" legend="Servers (targets)" />
        </Form.Item>
        <Form.Item name="roles" noStyle>
          <SelectorEditor kind="role" legend="Roles" />
        </Form.Item>
        <Form.Item name="enabled" valuePropName="checked">
          <Checkbox>Enabled</Checkbox>
        </Form.Item>
        <FormProblems errors={state.errors} apiError={state.apiError} />
      </Form>
    </Drawer>
  );
}

/** Create or edit an approver rule (docs/PLAN.md §9.7). `rule` undefined = create. */
export function ApproverRuleDrawer({
  open,
  rule,
  onClose,
}: {
  open: boolean;
  rule: ApproverRule | undefined;
  onClose: () => void;
}) {
  const [form] = Form.useForm<ApproverFormValues>();
  const queryClient = useQueryClient();
  const state = useSubmitState();

  useEffect(() => {
    if (open) {
      form.setFieldsValue(rule ? approverToForm(rule) : newApproverForm());
    }
  }, [open, rule, form]);

  const close = () => {
    // Fresh errors and a fresh Idempotency-Key for the next opening.
    state.reset();
    onClose();
  };

  const submit = async () => {
    const values = { ...newApproverForm(), ...form.getFieldsValue(true) } as ApproverFormValues;
    const { body, errors } = formToApproverBody(values);
    state.setErrors(errors);
    state.setApiError(null);
    if (!body) {
      return;
    }
    state.setPending(true);
    try {
      if (rule?.id) {
        await api.call('patch', '/api/v1/policy/approver-rules/{id}', {
          path: { id: rule.id },
          body,
          ...(rule.version !== undefined ? { ifMatch: rule.version } : {}),
        });
      } else {
        await api.call('post', '/api/v1/policy/approver-rules', {
          body,
          idempotencyKey: state.idempotencyKey,
        });
      }
      await queryClient.invalidateQueries({ queryKey: qk.policy });
      close();
    } catch (e) {
      applyFieldErrors(form, e);
      state.setApiError(e);
    } finally {
      state.setPending(false);
    }
  };

  return (
    <Drawer
      open={open}
      onClose={() => {
        if (!state.pending) {
          close();
        }
      }}
      title={rule ? `Edit approver rule “${rule.name}”` : 'New approver rule'}
      size="large"
      destroyOnHidden
      mask={{ closable: !state.pending }}
      footer={
        <Space style={{ justifyContent: 'flex-end', width: '100%' }}>
          <Button onClick={close} disabled={state.pending}>
            Cancel
          </Button>
          <Button type="primary" loading={state.pending} onClick={() => void submit()}>
            {rule ? 'Save approver rule' : 'Create approver rule'}
          </Button>
        </Space>
      }
    >
      <Form<ApproverFormValues> form={form} layout="vertical" requiredMark={false} aria-label="Approver rule">
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          title="Approver rules grant authority to decide requests"
          description="Operators matched here (with the approver role) may approve or deny requests for the matching servers and roles. Approvers can never approve their own requests."
        />
        <Form.Item label="Name" name="name" rules={[{ required: true, message: 'Enter a name' }]}>
          <Input maxLength={128} />
        </Form.Item>
        <Form.Item label="Description" name="description">
          <Input.TextArea maxLength={2000} autoSize={{ minRows: 1, maxRows: 4 }} />
        </Form.Item>
        <Form.Item name="operators" noStyle>
          <SelectorEditor kind="operator" legend="Approvers (operators)" />
        </Form.Item>
        <Form.Item name="targets" noStyle>
          <SelectorEditor kind="target" legend="Servers (targets)" />
        </Form.Item>
        <Form.Item name="roles" noStyle>
          <SelectorEditor kind="role" legend="Roles" />
        </Form.Item>
        <Form.Item
          label="Maximum approvable duration"
          name="max_duration"
          extra="Leave empty for no approver-specific limit (role and rule limits still apply)."
        >
          <DurationInput aria-label="Maximum approvable duration" minSeconds={60} />
        </Form.Item>
        <Form.Item name="enabled" valuePropName="checked">
          <Checkbox>Enabled</Checkbox>
        </Form.Item>
        <FormProblems errors={state.errors} apiError={state.apiError} />
      </Form>
    </Drawer>
  );
}
