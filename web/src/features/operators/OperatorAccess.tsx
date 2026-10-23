import { useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Form, Select, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { qk } from '../../api/queryKeys';
import type { Operator } from '../../api/types';
import { TagsInput } from '../../ds/TagsInput';
import { applyFieldErrors } from '../../lib/formErrors';
import { manualRoles, OPERATOR_ROLES, roleLabel, ssoRoles } from './roles';

interface Values {
  roles: string[];
  groups: string[];
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const sa = new Set(a);
  return sa.size === new Set(b).size && b.every((x) => sa.has(x));
}

/**
 * Manual roles and operator groups. SSO-mapped roles are read-only here (the provider's group mappings
 * own them). Changes apply only after the server confirms (no optimistic update).
 */
export function OperatorAccess({ operator }: { operator: Operator }) {
  const [form] = Form.useForm<Values>();
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const initialRoles = manualRoles(operator);
  const initialGroups = operator.groups ?? [];
  const sso = ssoRoles(operator);

  const submit = async (values: Values) => {
    const body: { roles?: string[]; groups?: string[] } = {};
    if (!sameSet(values.roles, initialRoles)) {
      body.roles = values.roles;
    }
    if (!sameSet(values.groups, initialGroups)) {
      body.groups = values.groups;
    }
    if (body.roles === undefined && body.groups === undefined) {
      void message.info('No changes to save');
      return;
    }
    setPending(true);
    setError(null);
    try {
      await api.call('patch', '/api/v1/operators/{id}', { path: { id: operator.id }, body });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.operator(operator.id) }),
        queryClient.invalidateQueries({ queryKey: qk.operators }),
        queryClient.invalidateQueries({ queryKey: qk.me }),
      ]);
      void message.success('Access updated');
    } catch (e) {
      applyFieldErrors(form, e);
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Form<Values>
      form={form}
      layout="vertical"
      requiredMark={false}
      initialValues={{ roles: initialRoles, groups: initialGroups }}
      onFinish={(v) => void submit(v)}
      aria-label="Roles and groups"
      key={String(operator.version)}
    >
      <Form.Item
        label="Manual roles"
        name="roles"
        extra="Roles assigned in Hallpass. Changes take effect at the operator's next request."
      >
        <Select
          mode="multiple"
          aria-label="Manual roles"
          options={OPERATOR_ROLES.map((r) => ({ value: r.value, label: `${r.label} — ${r.description}` }))}
        />
      </Form.Item>
      {sso.length > 0 ? (
        <div style={{ marginBottom: 16 }}>
          <div>Roles managed by SSO</div>
          <ul aria-label="Roles managed by SSO" style={{ margin: '4px 0 0', paddingInlineStart: 20 }}>
            {sso.map((r) => (
              <li key={`${r.role}|${r.ref ?? ''}`}>
                {roleLabel(r.role)}
                {r.ref ? <span className="hp-mono"> (from {r.ref})</span> : null} — managed by SSO group
                mappings
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <Form.Item
        label="Groups"
        name="groups"
        extra="Operator groups used by approver rules. Press Enter or comma after each name."
      >
        <TagsInput aria-label="Groups" placeholder="e.g. oncall" />
      </Form.Item>
      {error !== null ? (
        <Alert type="error" showIcon title={errorMessage(error)} style={{ marginBottom: 16 }} />
      ) : null}
      <Space>
        <Button type="primary" htmlType="submit" loading={pending}>
          Save access
        </Button>
        <Button
          disabled={pending}
          onClick={() => {
            form.resetFields();
            setError(null);
          }}
        >
          Reset
        </Button>
      </Space>
    </Form>
  );
}
