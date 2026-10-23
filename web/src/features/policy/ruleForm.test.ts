import { describe, expect, it } from 'vitest';

import type { ApproverRule, PolicyRule } from '../../api/types';
import {
  approverToForm,
  formToApproverBody,
  formToRuleBody,
  newApproverForm,
  newRuleForm,
  ruleToForm,
} from './ruleForm';

const rule: PolicyRule = {
  id: 'pol_1',
  name: 'ci to prod',
  description: 'deploys',
  effect: 'allow',
  level: 'auto_approve',
  subjects: { agent_groups: ['ci'] },
  targets: { all: true },
  roles: { names: ['deploy'] },
  max_duration: 3600,
  auto_max_duration: 900,
  require_reason: true,
  enabled: true,
  version: 3,
};

describe('policy rule form', () => {
  it('round-trips an existing rule into an identical body (without id/version)', () => {
    const { body, errors } = formToRuleBody(ruleToForm(rule));
    expect(errors).toEqual([]);
    const { id: _id, version: _v, ...expected } = rule;
    expect(body).toEqual(expected);
  });

  it('deny rules carry no level or durations', () => {
    const form = { ...ruleToForm(rule), effect: 'deny' as const };
    const { body } = formToRuleBody(form);
    expect(body).not.toBeNull();
    expect(body).not.toHaveProperty('level');
    expect(body).not.toHaveProperty('max_duration');
    expect(body).not.toHaveProperty('auto_max_duration');
  });

  it('auto-approve needs a limit of at least 1 minute that does not exceed the maximum', () => {
    const base = ruleToForm(rule);
    expect(formToRuleBody({ ...base, auto_max_duration: null }).errors).toContain(
      'Auto-approve rules need an auto-approval limit of at least 1 minute.',
    );
    expect(formToRuleBody({ ...base, auto_max_duration: 7200 }).errors).toContain(
      'The auto-approval limit cannot exceed the maximum duration.',
    );
    // Non-auto levels drop the auto limit entirely.
    const { body } = formToRuleBody({ ...base, level: 'requestable' });
    expect(body).not.toHaveProperty('auto_max_duration');
  });

  it('rejects empty selectors and a missing name', () => {
    const { body, errors } = formToRuleBody(newRuleForm());
    expect(body).toBeNull();
    expect(errors).toEqual([
      'Name is required.',
      'Agents: the selector is empty and would match nothing.',
      'Servers: the selector is empty and would match nothing.',
      'Roles: the selector is empty and would match nothing.',
    ]);
  });

  it('rejects sub-minute durations', () => {
    const { errors } = formToRuleBody({ ...ruleToForm(rule), level: 'requestable', max_duration: 30 });
    expect(errors).toContain('Maximum duration must be at least 1 minute.');
  });
});

describe('approver rule form', () => {
  const approver: ApproverRule = {
    id: 'apr_1',
    name: 'on-call',
    operators: { operator_groups: ['oncall'] },
    targets: { server_groups: ['prod'] },
    roles: { all: true },
    max_duration: 1800,
    enabled: false,
    version: 1,
  };

  it('round-trips', () => {
    const { body, errors } = formToApproverBody(approverToForm(approver));
    expect(errors).toEqual([]);
    const { id: _id, version: _v, ...expected } = approver;
    expect(body).toEqual(expected);
  });

  it('requires non-empty selectors', () => {
    const { errors } = formToApproverBody({ ...newApproverForm(), name: 'x' });
    expect(errors).toHaveLength(3);
    expect(errors[0]).toMatch(/^Approvers:/);
  });
});
