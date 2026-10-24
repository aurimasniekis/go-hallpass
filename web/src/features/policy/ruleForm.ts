import type { ApproverRule, PolicyRule } from '../../api/types';
import { formatDuration } from '../../lib/format';
import {
  emptySelectorForm,
  formToSelector,
  isSelectorEmpty,
  selectorToForm,
  type SelectorForm,
} from './selectors/model';

/**
 * Policy rule and approver rule form state ↔ request bodies (docs/PLAN.md §9.1, §9.7). Bodies contain
 * only spec fields: the server decodes with unknown fields disallowed. Durations are seconds.
 */

export type RuleEffect = 'allow' | 'deny';
export type RuleLevel = 'visible' | 'requestable' | 'auto_approve';

export interface RuleFormValues {
  name: string;
  description: string;
  effect: RuleEffect;
  level: RuleLevel;
  subjects: SelectorForm;
  targets: SelectorForm;
  roles: SelectorForm;
  max_duration: number | null;
  auto_max_duration: number | null;
  require_reason: boolean;
  enabled: boolean;
}

export type RuleBody = Omit<PolicyRule, 'id' | 'version'>;

export interface BuildResult<T> {
  body: T | null;
  errors: string[];
}

/** Minimum non-zero duration accepted by the server for rule limits (1 minute). */
export const MIN_RULE_DURATION = 60;

/** API limits use 0/absent for "no limit"; the form uses null. */
function positiveOrNull(seconds: number | undefined): number | null {
  return seconds !== undefined && seconds > 0 ? seconds : null;
}

export function newRuleForm(): RuleFormValues {
  return {
    name: '',
    description: '',
    effect: 'allow',
    level: 'requestable',
    subjects: emptySelectorForm(),
    targets: emptySelectorForm(),
    roles: emptySelectorForm(),
    max_duration: null,
    auto_max_duration: null,
    // The server defaults an omitted require_reason to true; new rules start from the same safe default.
    require_reason: true,
    enabled: true,
  };
}

export function ruleToForm(rule: PolicyRule): RuleFormValues {
  return {
    name: rule.name,
    description: rule.description ?? '',
    effect: rule.effect,
    level: rule.level ?? 'requestable',
    subjects: selectorToForm('subject', rule.subjects),
    targets: selectorToForm('target', rule.targets),
    roles: selectorToForm('role', rule.roles),
    max_duration: positiveOrNull(rule.max_duration),
    auto_max_duration: positiveOrNull(rule.auto_max_duration),
    require_reason: rule.require_reason,
    enabled: rule.enabled,
  };
}

function selectors(
  values: { subjects?: SelectorForm; targets?: SelectorForm; roles?: SelectorForm; operators?: SelectorForm },
  errors: string[],
) {
  const out: Record<string, Record<string, unknown>> = {};
  const entries: [string, 'subject' | 'target' | 'role' | 'operator', SelectorForm | undefined, string][] = [
    ['subjects', 'subject', values.subjects, 'Agents'],
    ['operators', 'operator', values.operators, 'Approvers'],
    ['targets', 'target', values.targets, 'Servers'],
    ['roles', 'role', values.roles, 'Roles'],
  ];
  for (const [field, kind, form, label] of entries) {
    if (form === undefined) {
      continue;
    }
    const built = formToSelector(kind, form);
    errors.push(...built.errors.map((e) => `${label}: ${e}`));
    if (isSelectorEmpty(kind, form)) {
      errors.push(`${label}: the selector is empty and would match nothing.`);
    }
    out[field] = built.selector;
  }
  return out;
}

function checkDuration(label: string, value: number | null, errors: string[]): void {
  if (value !== null && value !== 0 && value < MIN_RULE_DURATION) {
    errors.push(`${label} must be at least 1 minute.`);
  }
}

export function formToRuleBody(values: RuleFormValues): BuildResult<RuleBody> {
  const errors: string[] = [];
  const name = values.name.trim();
  if (name === '') {
    errors.push('Name is required.');
  }
  const sel = selectors({ subjects: values.subjects, targets: values.targets, roles: values.roles }, errors);
  const body: RuleBody = {
    name,
    effect: values.effect,
    subjects: sel.subjects ?? {},
    targets: sel.targets ?? {},
    roles: sel.roles ?? {},
    require_reason: values.require_reason,
    enabled: values.enabled,
  };
  if (values.description.trim() !== '') {
    body.description = values.description.trim();
  }
  if (values.effect === 'allow') {
    body.level = values.level;
    checkDuration('Maximum duration', values.max_duration, errors);
    if (values.max_duration) {
      body.max_duration = values.max_duration;
    }
    if (values.level === 'auto_approve') {
      const auto = values.auto_max_duration ?? 0;
      if (auto < MIN_RULE_DURATION) {
        errors.push('Auto-approve rules need an auto-approval limit of at least 1 minute.');
      } else if (values.max_duration && auto > values.max_duration) {
        errors.push('The auto-approval limit cannot exceed the maximum duration.');
      }
      if (auto) {
        body.auto_max_duration = auto;
      }
    }
  }
  return { body: errors.length ? null : body, errors };
}

export interface ApproverFormValues {
  name: string;
  description: string;
  operators: SelectorForm;
  targets: SelectorForm;
  roles: SelectorForm;
  max_duration: number | null;
  enabled: boolean;
}

export type ApproverBody = Omit<ApproverRule, 'id' | 'version'>;

export function newApproverForm(): ApproverFormValues {
  return {
    name: '',
    description: '',
    operators: emptySelectorForm(),
    targets: emptySelectorForm(),
    roles: emptySelectorForm(),
    max_duration: null,
    enabled: true,
  };
}

export function approverToForm(rule: ApproverRule): ApproverFormValues {
  return {
    name: rule.name,
    description: rule.description ?? '',
    operators: selectorToForm('operator', rule.operators),
    targets: selectorToForm('target', rule.targets),
    roles: selectorToForm('role', rule.roles),
    max_duration: positiveOrNull(rule.max_duration),
    enabled: rule.enabled,
  };
}

export function formToApproverBody(values: ApproverFormValues): BuildResult<ApproverBody> {
  const errors: string[] = [];
  const name = values.name.trim();
  if (name === '') {
    errors.push('Name is required.');
  }
  const sel = selectors(
    { operators: values.operators, targets: values.targets, roles: values.roles },
    errors,
  );
  checkDuration('Maximum approvable duration', values.max_duration, errors);
  const body: ApproverBody = {
    name,
    operators: sel.operators ?? {},
    targets: sel.targets ?? {},
    roles: sel.roles ?? {},
    enabled: values.enabled,
  };
  if (values.description.trim() !== '') {
    body.description = values.description.trim();
  }
  if (values.max_duration) {
    body.max_duration = values.max_duration;
  }
  return { body: errors.length ? null : body, errors };
}

export const LEVEL_LABEL: Record<RuleLevel, string> = {
  visible: 'Visible',
  requestable: 'Requestable',
  auto_approve: 'Auto-approve',
};

/** `—` for unset (0/undefined) limits, which mean "no rule-specific limit". */
export function limitText(seconds: number | undefined): string {
  return seconds ? formatDuration(seconds) : '—';
}
