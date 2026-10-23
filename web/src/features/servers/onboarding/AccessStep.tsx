import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Alert, Button, Card, Checkbox, Radio, Select, Space, Switch } from 'antd';
import { useId, useState, type ReactNode } from 'react';

import { api } from '../../../api/client';
import { errorMessage } from '../../../api/errors';
import { groupsQueryOptions, operatorsQueryOptions } from '../../../api/queries';
import { qk } from '../../../api/queryKeys';
import type { PolicyRule, Role, Server } from '../../../api/types';
import { DurationInput } from '../../../ds/DurationInput';
import { formatDuration } from '../../../lib/format';
import { newIdempotencyKey } from '../../../lib/idempotency';
import { usePermissions } from '../../../lib/usePermissions';
import { LEVEL_LABEL } from '../../policy/ruleForm';
import { accessBodies, newAccessForm, type AccessForm } from './model';

function Field({
  label,
  children,
  hint,
  group = false,
}: {
  label: string;
  children: (id: string) => ReactNode;
  hint?: string;
  /** Checkbox or radio groups are named by the label instead of being its control. */
  group?: boolean;
}) {
  const id = useId();
  return (
    <div className="hp-field">
      {group ? (
        <>
          <span id={`${id}-label`} className="hp-field__label">
            {label}
          </span>
          <div role="group" aria-labelledby={`${id}-label`}>
            {children(id)}
          </div>
        </>
      ) : (
        <>
          <label htmlFor={id} className="hp-field__label">
            {label}
          </label>
          {children(id)}
        </>
      )}
      {hint ? <div className="hp-legend">{hint}</div> : null}
    </div>
  );
}

/**
 * Access step: optionally create one policy rule (agent groups → this server's roles) and one approver
 * rule. Both are ordinary rules, editable later on the Policy page.
 */
export function AccessStep({
  server,
  roles,
  rules,
  onDone,
  onSkip,
}: {
  server: Server;
  roles: Role[];
  /** Existing rules that target this server. */
  rules: PolicyRule[] | undefined;
  onDone: () => void;
  onSkip: () => void;
}) {
  const { can, me } = usePermissions();
  const queryClient = useQueryClient();
  const agentGroups = useQuery({ ...groupsQueryOptions('agent'), enabled: can('inventory.read') });
  const operatorGroups = useQuery({ ...groupsQueryOptions('operator'), enabled: can('inventory.read') });
  const operators = useQuery({ ...operatorsQueryOptions(), enabled: can('operators.manage') });
  const [form, setForm] = useState<AccessForm>(() => ({
    ...newAccessForm(roles.map((r) => r.id)),
    approverOperatorIds: me ? [me.operator.id] : [],
  }));
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [created, setCreated] = useState<string[]>([]);
  const [keys] = useState(() => ({ rule: newIdempotencyKey(), approver: newIdempotencyKey() }));
  const set = (patch: Partial<AccessForm>) => {
    setForm((f) => ({ ...f, ...patch }));
  };
  const built = accessBodies(form, server);
  const canWrite = can('policy.write');

  const submit = async () => {
    if (!built.rule) {
      return;
    }
    setPending(true);
    setError(null);
    const done: string[] = [...created];
    try {
      if (!done.includes('rule')) {
        await api.call('post', '/api/v1/policy/rules', { body: built.rule, idempotencyKey: keys.rule });
        done.push('rule');
        setCreated([...done]);
      }
      if (built.approver && !done.includes('approver')) {
        await api.call('post', '/api/v1/policy/approver-rules', { body: built.approver });
        done.push('approver');
        setCreated([...done]);
      }
      await queryClient.invalidateQueries({ queryKey: qk.policy });
      await queryClient.invalidateQueries({ queryKey: qk.effectiveAccess });
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  const operatorOptions = operators.data
    ? operators.data.items.map((o) => ({ value: o.id, label: `${o.display_name} (${o.email})` }))
    : me
      ? [{ value: me.operator.id, label: `${me.operator.display_name} (you)` }]
      : [];

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      {rules && rules.length > 0 ? (
        <Alert
          type="success"
          showIcon
          title={`${String(rules.length)} access rule${rules.length === 1 ? '' : 's'} already cover this server`}
          description={
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {rules.map((r) => (
                <li key={r.id ?? r.name}>
                  <strong>{r.name}</strong> —{' '}
                  {r.effect === 'deny' ? 'deny' : LEVEL_LABEL[r.level ?? 'requestable']}
                  {r.max_duration ? `, up to ${formatDuration(r.max_duration)}` : ''}
                </li>
              ))}
            </ul>
          }
        />
      ) : null}
      {!canWrite ? (
        <Alert
          type="info"
          showIcon
          title="Creating access rules needs the policy.write permission"
          description="Skip this step; an administrator can add rules on the Policy page."
        />
      ) : (
        <Card size="small" title="Who may use this server">
          <div className="hp-form-grid">
            <Field label="Agent groups" hint="Agents in any of these groups get access.">
              {(id) => (
                <Select
                  id={id}
                  mode="tags"
                  aria-label="Agent groups"
                  value={form.agentGroups}
                  onChange={(v: string[]) => {
                    set({ agentGroups: v });
                  }}
                  placeholder="Type or choose agent groups"
                  options={(agentGroups.data?.items ?? []).map((g) => ({ value: g.name, label: g.name }))}
                  style={{ width: '100%' }}
                />
              )}
            </Field>
            <Field label="Roles" group>
              {() => (
                <Checkbox.Group
                  value={form.roleIds}
                  onChange={(v) => {
                    set({ roleIds: v });
                  }}
                  options={roles.map((r) => ({ value: r.id, label: `${r.alias} (${r.remote_user})` }))}
                />
              )}
            </Field>
            <Field
              label="Access level"
              hint={
                form.level === 'auto_approve'
                  ? 'Requests up to the auto-approval limit are granted without a human.'
                  : 'Every request waits for an approver.'
              }
              group
            >
              {() => (
                <Radio.Group
                  value={form.level}
                  onChange={(e) => {
                    set({ level: e.target.value as AccessForm['level'] });
                  }}
                  options={[
                    { value: 'requestable', label: 'Requestable (needs approval)' },
                    { value: 'auto_approve', label: 'Auto-approve' },
                  ]}
                />
              )}
            </Field>
            <Field label="Maximum duration" hint="Optional; the role's maximum applies when unset.">
              {(id) => (
                <DurationInput
                  id={id}
                  aria-label="Maximum duration"
                  minSeconds={60}
                  value={form.maxDuration}
                  onChange={(v) => {
                    set({ maxDuration: v });
                  }}
                />
              )}
            </Field>
            {form.level === 'auto_approve' ? (
              <Field label="Auto-approve up to">
                {(id) => (
                  <DurationInput
                    id={id}
                    aria-label="Auto-approve up to"
                    minSeconds={60}
                    value={form.autoMaxDuration}
                    onChange={(v) => {
                      set({ autoMaxDuration: v });
                    }}
                  />
                )}
              </Field>
            ) : null}
            <Field label="Require a reason">
              {(id) => (
                <Switch
                  id={id}
                  checked={form.requireReason}
                  onChange={(v) => {
                    set({ requireReason: v });
                  }}
                />
              )}
            </Field>
          </div>
          <div className="hp-form-section">
            <Space align="center">
              <Switch
                checked={form.approver}
                aria-label="Also create an approver rule"
                onChange={(v) => {
                  set({ approver: v });
                }}
              />
              <span aria-hidden="true">Also create an approver rule for this server</span>
            </Space>
            {form.approver ? (
              <div className="hp-form-grid" style={{ marginTop: 12 }}>
                <Field label="Approvers">
                  {(id) => (
                    <Select
                      id={id}
                      mode="multiple"
                      aria-label="Approvers"
                      value={form.approverOperatorIds}
                      onChange={(v: string[]) => {
                        set({ approverOperatorIds: v });
                      }}
                      options={operatorOptions}
                      showSearch={{ optionFilterProp: 'label' }}
                      style={{ width: '100%' }}
                    />
                  )}
                </Field>
                <Field label="Approver groups" hint="Operators in these groups may approve too.">
                  {(id) => (
                    <Select
                      id={id}
                      mode="tags"
                      aria-label="Approver groups"
                      value={form.approverOperatorGroups}
                      onChange={(v: string[]) => {
                        set({ approverOperatorGroups: v });
                      }}
                      options={(operatorGroups.data?.items ?? []).map((g) => ({
                        value: g.name,
                        label: g.name,
                      }))}
                      style={{ width: '100%' }}
                    />
                  )}
                </Field>
              </div>
            ) : null}
          </div>
          {built.errors.length > 0 ? (
            <ul
              className="hp-legend"
              aria-label="Missing input"
              style={{ margin: '12px 0 0', paddingLeft: 18 }}
            >
              {built.errors.map((e) => (
                <li key={e}>{e}</li>
              ))}
            </ul>
          ) : (
            <p className="hp-legend" style={{ margin: '12px 0 0' }}>
              Creates rule <code className="hp-mono">{built.rule?.name}</code>
              {built.approver ? (
                <>
                  {' '}
                  and approver rule <code className="hp-mono">{built.approver.name}</code>
                </>
              ) : null}
              . Edit them later on the <Link to="/policy">Policy</Link> page.
            </p>
          )}
          {error !== null ? (
            <Alert
              style={{ marginTop: 12 }}
              type="error"
              showIcon
              title={
                created.includes('rule')
                  ? 'The access rule was created, but the approver rule failed'
                  : 'Could not create the access rule'
              }
              description={errorMessage(error)}
            />
          ) : null}
        </Card>
      )}
      <Space wrap>
        {canWrite ? (
          <Button type="primary" loading={pending} disabled={!built.rule} onClick={() => void submit()}>
            {created.includes('rule') ? 'Retry approver rule' : 'Create access rules'}
          </Button>
        ) : null}
        <Button onClick={onSkip}>{rules && rules.length > 0 ? 'Continue' : 'Skip for now'}</Button>
      </Space>
    </Space>
  );
}
