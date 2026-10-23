import type {
  ApproverRule,
  HostIdentity,
  LoginCredential,
  PolicyRule,
  Role,
  Server,
} from '../../../api/types';
import { isPlainUserName, shellQuote } from '../../../lib/shell';
import { MIN_RULE_DURATION, type ApproverBody, type RuleBody } from '../../policy/ruleForm';

/**
 * Server onboarding wizard (nothing → a working login): the step logic, kept pure so it can be tested.
 * Every fact is derived from server data, so the wizard can be abandoned and resumed from the server page
 * at any time: resources already created are found again, never duplicated.
 */

export const STEPS = ['server', 'identity', 'roles', 'credentials', 'access', 'done'] as const;
export type StepKey = (typeof STEPS)[number];

export const STEP_TITLES: Record<StepKey, string> = {
  server: 'Server',
  identity: 'Host identity',
  roles: 'Roles',
  credentials: 'Login credentials',
  access: 'Access',
  done: 'Summary',
};

export function parseStep(value: unknown): StepKey | undefined {
  return typeof value === 'string' && (STEPS as readonly string[]).includes(value)
    ? (value as StepKey)
    : undefined;
}

export type RoleLogin =
  /** An active (or retiring) login key: the gateway can log in. */
  | 'active'
  /** Certificate binding made in this wizard session (the API does not report bindings). */
  | 'certificate'
  /** A key exists but is not active yet (install → probe → activate). */
  | 'pending'
  | 'none'
  /** Credentials could not be read (no credentials.manage, or still loading). */
  | 'unknown';

export function roleLogin(
  credentials: readonly Pick<LoginCredential, 'state'>[] | undefined,
  certificateBound = false,
): RoleLogin {
  if (credentials === undefined) {
    return certificateBound ? 'certificate' : 'unknown';
  }
  if (credentials.some((c) => c.state === 'active' || c.state === 'retiring')) {
    return 'active';
  }
  if (certificateBound) {
    return 'certificate';
  }
  return credentials.some((c) => c.state === 'pending') ? 'pending' : 'none';
}

/** Newest pending credential: the one the operator is installing and testing. */
export function focusCredential<T extends Pick<LoginCredential, 'state' | 'created_at'>>(
  credentials: readonly T[] | undefined,
): T | undefined {
  return [...(credentials ?? [])]
    .filter((c) => c.state === 'pending')
    .sort((a, b) => b.created_at.localeCompare(a.created_at))[0];
}

export interface WizardFacts {
  server: Pick<Server, 'id' | 'active_host_identities' | 'host_ca_id'> | null;
  /** Host identities of the server, when readable. */
  identities?: readonly Pick<HostIdentity, 'state'>[] | undefined;
  roles?: readonly Pick<Role, 'id' | 'enabled'>[] | undefined;
  /** Login status per role ID. */
  logins?: Readonly<Record<string, RoleLogin>>;
  /** Policy rules that target this server. */
  accessRules?: readonly unknown[] | undefined;
  /** The operator chose to skip the optional access step in this session. */
  accessSkipped?: boolean;
}

export interface StepState {
  key: StepKey;
  done: boolean;
  /** The step can be opened (its prerequisites exist). */
  available: boolean;
}

export function identityDone(f: WizardFacts): boolean {
  if (!f.server) {
    return false;
  }
  if (f.server.host_ca_id) {
    return true;
  }
  if (f.identities) {
    return f.identities.some((h) => h.state === 'active');
  }
  return (f.server.active_host_identities ?? 0) > 0;
}

export function credentialsDone(f: WizardFacts): boolean {
  const roles = (f.roles ?? []).filter((r) => r.enabled);
  if (roles.length === 0) {
    return false;
  }
  return roles.every((r) => {
    const login = f.logins?.[r.id];
    return login === 'active' || login === 'certificate';
  });
}

export function stepStates(f: WizardFacts): StepState[] {
  const hasServer = f.server !== null;
  const hasRoles = (f.roles ?? []).length > 0;
  const done: Record<StepKey, boolean> = {
    server: hasServer,
    identity: identityDone(f),
    roles: hasRoles,
    credentials: credentialsDone(f),
    access: (f.accessRules ?? []).length > 0 || Boolean(f.accessSkipped),
    done: false,
  };
  const available: Record<StepKey, boolean> = {
    server: true,
    identity: hasServer,
    roles: hasServer,
    credentials: hasRoles,
    access: hasRoles,
    done: hasServer,
  };
  done.done = done.server && done.identity && done.roles && done.credentials && done.access;
  return STEPS.map((key) => ({ key, done: done[key], available: available[key] }));
}

/** Where to resume: the first step that is not done (the summary when everything is). */
export function resumeStep(f: WizardFacts): StepKey {
  return stepStates(f).find((s) => !s.done && s.key !== 'done')?.key ?? 'done';
}

/** The requested step if it can be opened, otherwise where to resume. */
export function effectiveStep(requested: StepKey | undefined, f: WizardFacts): StepKey {
  if (requested) {
    const s = stepStates(f).find((x) => x.key === requested);
    if (s?.available) {
      return requested;
    }
  }
  return resumeStep(f);
}

export function nextStep(step: StepKey): StepKey {
  return STEPS[Math.min(STEPS.indexOf(step) + 1, STEPS.length - 1)] ?? 'done';
}

export function previousStep(step: StepKey): StepKey {
  return STEPS[Math.max(STEPS.indexOf(step) - 1, 0)] ?? 'server';
}

/** Server pages offer "continue guided setup" while the basic onboarding is unfinished. */
export function needsOnboarding(
  server: Pick<Server, 'active_host_identities' | 'host_ca_id'>,
  roles: readonly unknown[] | undefined,
): boolean {
  const identity = Boolean(server.host_ca_id) || (server.active_host_identities ?? 0) > 0;
  return !identity || roles?.length === 0;
}

/**
 * Command that appends a generated `authorized_keys` line for the role's remote user, run on the
 * destination. The line is single-quoted, so nothing in it is interpreted by the shell.
 */
export function installCommand(authorizedKeysLine: string, remoteUser: string): string {
  const home = isPlainUserName(remoteUser) ? `~${remoteUser}` : '~<remote user>';
  return `echo ${shellQuote(authorizedKeysLine.trim())} | sudo tee -a ${home}/.ssh/authorized_keys`;
}

/** Prepares the user's ~/.ssh when it does not exist yet (sshd refuses group/world-writable paths). */
export function prepareSshDirCommand(remoteUser: string): string {
  const user = isPlainUserName(remoteUser) ? remoteUser : '<remote user>';
  return `sudo install -d -m 700 -o ${user} ~${user}/.ssh`;
}

/** Does a policy or approver rule's target selector name this server (or all servers)? */
export function targetsServer(rule: Pick<PolicyRule | ApproverRule, 'targets'>, serverId: string): boolean {
  const t = rule.targets as Record<string, unknown> | undefined;
  if (!t) {
    return false;
  }
  if (t.all === true) {
    return true;
  }
  return Array.isArray(t.servers) && t.servers.includes(serverId);
}

export type AccessLevel = 'requestable' | 'auto_approve';

export interface AccessForm {
  agentGroups: string[];
  roleIds: string[];
  level: AccessLevel;
  /** seconds; null = no rule-specific limit */
  maxDuration: number | null;
  /** seconds; auto-approve only */
  autoMaxDuration: number | null;
  requireReason: boolean;
  /** Create an approver rule for the operators below (requestable access needs someone to approve). */
  approver: boolean;
  approverOperatorIds: string[];
  approverOperatorGroups: string[];
}

export function newAccessForm(roleIds: string[]): AccessForm {
  return {
    agentGroups: [],
    roleIds,
    level: 'requestable',
    maxDuration: null,
    autoMaxDuration: 30 * 60,
    requireReason: true,
    approver: true,
    approverOperatorIds: [],
    approverOperatorGroups: [],
  };
}

const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40) || 'server';

export interface AccessBodies {
  rule: RuleBody | null;
  approver: ApproverBody | null;
  errors: string[];
}

/** Request bodies for the access step: one policy rule and, optionally, one approver rule. */
export function accessBodies(form: AccessForm, server: { id: string; alias: string }): AccessBodies {
  const errors: string[] = [];
  const groups = [...new Set(form.agentGroups.map((g) => g.trim()).filter(Boolean))];
  if (groups.length === 0) {
    errors.push('Choose at least one agent group.');
  }
  if (form.roleIds.length === 0) {
    errors.push('Choose at least one role.');
  }
  if (form.maxDuration !== null && form.maxDuration < MIN_RULE_DURATION) {
    errors.push('The maximum duration must be at least 1 minute.');
  }
  if (form.level === 'auto_approve') {
    const auto = form.autoMaxDuration ?? 0;
    if (auto < MIN_RULE_DURATION) {
      errors.push('Auto-approval needs a limit of at least 1 minute.');
    } else if (form.maxDuration && auto > form.maxDuration) {
      errors.push('The auto-approval limit cannot exceed the maximum duration.');
    }
  }
  const approverOps = [...new Set(form.approverOperatorIds)];
  const approverGroups = [...new Set(form.approverOperatorGroups.map((g) => g.trim()).filter(Boolean))];
  if (form.approver && approverOps.length === 0 && approverGroups.length === 0) {
    errors.push('Choose at least one approver (an operator or an operator group).');
  }
  if (errors.length > 0) {
    return { rule: null, approver: null, errors };
  }
  const base = slug(server.alias);
  const rule: RuleBody = {
    name: `${base}-${form.level === 'auto_approve' ? 'auto' : 'request'}`,
    description: `Created by the onboarding wizard for ${server.alias}.`,
    effect: 'allow',
    level: form.level,
    subjects: { agent_groups: groups },
    targets: { servers: [server.id] },
    roles: { ids: [...form.roleIds] },
    require_reason: form.requireReason,
    enabled: true,
  };
  if (form.maxDuration) {
    rule.max_duration = form.maxDuration;
  }
  if (form.level === 'auto_approve' && form.autoMaxDuration) {
    rule.auto_max_duration = form.autoMaxDuration;
  }
  const approver: ApproverBody | null = form.approver
    ? {
        name: `${base}-approvers`,
        description: `Created by the onboarding wizard for ${server.alias}.`,
        operators: {
          ...(approverOps.length > 0 ? { operators: approverOps } : {}),
          ...(approverGroups.length > 0 ? { operator_groups: approverGroups } : {}),
        },
        targets: { servers: [server.id] },
        roles: { ids: [...form.roleIds] },
        enabled: true,
      }
    : null;
  return { rule, approver, errors: [] };
}
