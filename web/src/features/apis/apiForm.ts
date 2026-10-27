import type { APIRule, Role } from '../../api/types';

type Effect = 'allow' | 'deny';
type Method = NonNullable<APIRule['methods']>[number];
type GraphQLType = NonNullable<APIRule['graphql']>[number];

export const METHODS: Method[] = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
export const GRAPHQL_TYPES: GraphQLType[] = ['query', 'mutation', 'subscription'];

/** One rule in the form; empty or missing lists mean "any" (Select clears to undefined). */
export interface ApiRuleFormValue {
  effect: Effect;
  methods?: Method[];
  hosts?: string[];
  paths?: string[];
  graphql?: GraphQLType[];
}

/** Form values of an API access profile. Durations are seconds. */
export interface ApiProfileFormValues {
  alias: string;
  description?: string;
  rules: ApiRuleFormValue[];
  approvals_required: number;
  default_duration: number;
  max_duration: number;
}

export function ruleFormValue(r: APIRule): ApiRuleFormValue {
  return {
    effect: r.effect,
    methods: r.methods ?? [],
    hosts: r.hosts ?? [],
    paths: r.paths ?? [],
    graphql: r.graphql ?? [],
  };
}

export function apiProfileDefaults(rules: APIRule[]): ApiProfileFormValues {
  return {
    alias: '',
    description: '',
    rules: rules.map(ruleFormValue),
    approvals_required: 1,
    default_duration: 3600,
    max_duration: 8 * 3600,
  };
}

function toRule(v: ApiRuleFormValue): APIRule {
  const r: APIRule = { effect: v.effect };
  const trim = (xs: readonly string[] | undefined) => (xs ?? []).map((x) => x.trim()).filter((x) => x !== '');
  if ((v.methods ?? []).length > 0) {
    r.methods = v.methods;
  }
  if (trim(v.hosts).length > 0) {
    r.hosts = trim(v.hosts);
  }
  if (trim(v.paths).length > 0) {
    r.paths = trim(v.paths);
  }
  if ((v.graphql ?? []).length > 0) {
    r.graphql = v.graphql;
  }
  return r;
}

/** Request body for creating or updating an API access profile. */
export function toApiProfileInput(v: ApiProfileFormValues) {
  return {
    alias: v.alias.trim(),
    description: (v.description ?? '').trim(),
    capabilities: ['api'],
    api: { rules: v.rules.map(toRule) },
    approvals_required: v.approvals_required,
    default_duration: v.default_duration,
    max_duration: v.max_duration,
  };
}

export function apiProfileFormValues(r: Role): ApiProfileFormValues {
  return {
    alias: r.alias,
    description: r.description ?? '',
    rules: (r.api?.rules ?? []).map(ruleFormValue),
    approvals_required: r.approvals_required ?? 1,
    default_duration: r.default_duration,
    max_duration: r.max_duration,
  };
}

/** One line per rule, for tables: "allow GET HEAD /repos/acme/**". */
export function ruleSummary(r: APIRule): string {
  const parts: string[] = [r.effect, (r.methods ?? []).join(' ') || 'any method'];
  if ((r.hosts ?? []).length > 0) {
    parts.push(`on ${(r.hosts ?? []).join(' ')}`);
  }
  parts.push((r.paths ?? []).join(' ') || 'any path');
  if ((r.graphql ?? []).length > 0) {
    parts.push(`(GraphQL ${(r.graphql ?? []).join(', ')})`);
  }
  return parts.join(' ');
}
