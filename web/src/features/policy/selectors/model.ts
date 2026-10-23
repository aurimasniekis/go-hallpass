import { labelsToTags, tagsToLabels } from '../../../lib/labels';

/**
 * Policy selectors (docs/PLAN.md §9.3, internal/policy/selectors.go). The API types them as an open
 * `Selector` object; these helpers convert between the wire shape and an editable form state, and are
 * the single place that knows each selector kind's field names. Union semantics across clauses; an
 * empty selector matches nothing (HP-POL-003); `all: true` also matches resources created later.
 */

export type SelectorKind = 'subject' | 'target' | 'role' | 'operator';

export const LABEL_OPERATORS = ['In', 'NotIn', 'Exists', 'DoesNotExist'] as const;
export type LabelOperator = (typeof LABEL_OPERATORS)[number];

export interface LabelExpression {
  key: string;
  operator: LabelOperator;
  values: string[];
}

/** Editable selector. Unused clauses for a kind stay empty. */
export interface SelectorForm {
  all: boolean;
  /** Agent, server, role or operator IDs. */
  ids: string[];
  /** Agent/server/operator group names. */
  groups: string[];
  /** Role aliases (role selectors only). */
  names: string[];
  /** `key=value` tags for `matchLabels`. */
  labels: string[];
  expressions: LabelExpression[];
}

interface KindFields {
  ids: string;
  groups?: string;
  names?: string;
  labels?: string;
}

export const KIND_FIELDS: Record<SelectorKind, KindFields> = {
  subject: { ids: 'agents', groups: 'agent_groups', labels: 'agent_labels' },
  target: { ids: 'servers', groups: 'server_groups', labels: 'server_labels' },
  role: { ids: 'ids', names: 'names', labels: 'role_labels' },
  operator: { ids: 'operators', groups: 'operator_groups' },
};

export const KIND_NOUN: Record<SelectorKind, { one: string; many: string }> = {
  subject: { one: 'agent', many: 'agents' },
  target: { one: 'server', many: 'servers' },
  role: { one: 'role', many: 'roles' },
  operator: { one: 'operator', many: 'operators' },
};

export function emptySelectorForm(): SelectorForm {
  return { all: false, ids: [], groups: [], names: [], labels: [], expressions: [] };
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

function isOperator(value: unknown): value is LabelOperator {
  return typeof value === 'string' && (LABEL_OPERATORS as readonly string[]).includes(value);
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** Wire selector (untyped server JSON) → form state. Unknown fields and malformed entries are ignored. */
export function selectorToForm(kind: SelectorKind, raw: unknown): SelectorForm {
  const sel = record(raw) ?? {};
  const f = KIND_FIELDS[kind];
  const form = emptySelectorForm();
  form.all = sel.all === true;
  form.ids = strings(sel[f.ids]);
  if (f.groups) {
    form.groups = strings(sel[f.groups]);
  }
  if (f.names) {
    form.names = strings(sel[f.names]);
  }
  if (f.labels) {
    const ls = record(sel[f.labels]);
    if (ls) {
      const ml = record(ls.matchLabels) ?? {};
      form.labels = labelsToTags(
        Object.fromEntries(Object.entries(ml).filter((e): e is [string, string] => typeof e[1] === 'string')),
      );
      form.expressions = (Array.isArray(ls.matchExpressions) ? ls.matchExpressions : [])
        .map(record)
        .filter(
          (r): r is Record<string, unknown> =>
            r !== null && typeof r.key === 'string' && isOperator(r.operator),
        )
        .map((r) => ({
          key: r.key as string,
          operator: r.operator as LabelOperator,
          values: strings(r.values),
        }));
    }
  }
  return form;
}

export interface SelectorBuild {
  selector: Record<string, unknown>;
  /** Human-readable problems that the server would reject (or that would silently match nothing). */
  errors: string[];
}

/** Form state → wire selector with only the kind's fields; empty clauses are omitted. */
export function formToSelector(kind: SelectorKind, form: SelectorForm): SelectorBuild {
  const f = KIND_FIELDS[kind];
  const out: Record<string, unknown> = {};
  const errors: string[] = [];
  if (form.all) {
    out.all = true;
  }
  const trim = (xs: string[]) => [...new Set(xs.map((x) => x.trim()).filter((x) => x !== ''))];
  const ids = trim(form.ids);
  if (ids.length) {
    out[f.ids] = ids;
  }
  if (f.groups) {
    const groups = trim(form.groups);
    if (groups.length) {
      out[f.groups] = groups;
    }
  }
  if (f.names) {
    const names = trim(form.names);
    if (names.length) {
      out[f.names] = names;
    }
  }
  if (f.labels) {
    const { labels, invalid } = tagsToLabels(form.labels);
    for (const bad of invalid) {
      errors.push(`Label "${bad}" must be written as key=value.`);
    }
    const expressions: { key: string; operator: LabelOperator; values?: string[] }[] = [];
    for (const e of form.expressions) {
      const key = e.key.trim();
      const values = trim(e.values);
      if (key === '') {
        errors.push('Every label expression needs a key.');
        continue;
      }
      if ((e.operator === 'In' || e.operator === 'NotIn') && values.length === 0) {
        errors.push(`Label expression "${key} ${e.operator}" needs at least one value.`);
      }
      if ((e.operator === 'Exists' || e.operator === 'DoesNotExist') && values.length > 0) {
        errors.push(`Label expression "${key} ${e.operator}" takes no values.`);
      }
      expressions.push(
        e.operator === 'In' || e.operator === 'NotIn'
          ? { key, operator: e.operator, values }
          : { key, operator: e.operator },
      );
    }
    const ls: Record<string, unknown> = {};
    if (Object.keys(labels).length) {
      ls.matchLabels = labels;
    }
    if (expressions.length) {
      ls.matchExpressions = expressions;
    }
    if (Object.keys(ls).length) {
      out[f.labels] = ls;
    }
  }
  return { selector: out, errors };
}

/** True when the selector matches nothing (no `all`, no IDs, groups, names or label clauses). */
export function isSelectorEmpty(kind: SelectorKind, form: SelectorForm): boolean {
  return Object.keys(formToSelector(kind, form).selector).length === 0;
}

export function describeExpression(e: LabelExpression): string {
  switch (e.operator) {
    case 'In':
      return `${e.key} in (${e.values.join(', ')})`;
    case 'NotIn':
      return `${e.key} not in (${e.values.join(', ')})`;
    case 'Exists':
      return `${e.key} exists`;
    case 'DoesNotExist':
      return `${e.key} absent`;
  }
}

/**
 * One-line summary of a wire selector for tables. `name` resolves IDs to display names when known.
 */
export function summarizeSelector(
  kind: SelectorKind,
  raw: unknown,
  name: (id: string) => string = (id) => id,
): string {
  const form = selectorToForm(kind, raw);
  const noun = KIND_NOUN[kind];
  if (isSelectorEmpty(kind, form)) {
    return `No ${noun.many} (empty selector)`;
  }
  const parts: string[] = [];
  if (form.all) {
    parts.push(`All ${noun.many}`);
  }
  if (form.ids.length) {
    parts.push(`${form.ids.length === 1 ? noun.one : noun.many}: ${form.ids.map(name).join(', ')}`);
  }
  if (form.names.length) {
    parts.push(`names: ${form.names.join(', ')}`);
  }
  if (form.groups.length) {
    parts.push(`groups: ${form.groups.join(', ')}`);
  }
  const labelParts = [...form.labels, ...form.expressions.map(describeExpression)];
  if (labelParts.length) {
    parts.push(`labels: ${labelParts.join(' and ')}`);
  }
  return parts.join('; ');
}
