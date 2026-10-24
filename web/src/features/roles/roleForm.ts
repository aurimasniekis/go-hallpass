import type { Role, RoleInput } from '../../api/types';
import { labelsToTags } from '../../lib/labels';
import { cleanList, labelsFromTags } from '../servers/formUtils';

export const CAPABILITIES = [
  { value: 'shell', label: 'Interactive shell' },
  { value: 'exec', label: 'Command execution (exec)' },
  { value: 'pty', label: 'Terminal (PTY) allocation' },
  { value: 'file-transfer', label: 'File transfer (scp, sftp)' },
] as const;

export const APPROVAL_CHANNELS = [
  { value: 'web', label: 'Web console' },
  { value: 'slack', label: 'Slack' },
  { value: 'telegram', label: 'Telegram' },
] as const;

export const RECORDING_MODES = [
  { value: 'mandatory', label: 'Mandatory — refuse the channel if recording fails' },
  { value: 'best_effort', label: 'Best effort — continue and flag the session if recording fails' },
] as const;

/** Server defaults for new roles (internal/inventory/roles.go CreateRole). */
export const ROLE_DEFAULTS: RoleFormValues = {
  alias: '',
  remote_user: '',
  capabilities: ['shell', 'exec', 'pty'],
  default_duration: 30 * 60,
  max_duration: 6 * 3600,
  max_concurrent: 10,
  max_concurrent_per_agent: 2,
  recording_mode: 'mandatory',
  record_input: false,
  approval_channels: ['web', 'slack', 'telegram'],
  approvals_required: 1,
  retention_class: 'default',
  enabled: true,
};

export interface RoleFormValues {
  alias: string;
  display_name?: string;
  description?: string;
  remote_user: string;
  capabilities?: string[];
  /** seconds */
  default_duration?: number | null;
  /** seconds */
  max_duration?: number | null;
  max_concurrent?: number | null;
  max_concurrent_per_agent?: number | null;
  recording_mode?: string;
  record_input?: boolean;
  env_allow?: string[];
  approval_channels?: string[];
  approvals_required?: number;
  restriction_notes?: string;
  retention_class?: string;
  labels?: string[];
  enabled?: boolean;
}

/** Durations are integer seconds in the API (ADR-0031). Unset numbers are omitted (server keeps/defaults). */
export function toRoleInput(v: RoleFormValues, version?: number): RoleInput {
  const body: RoleInput = {
    alias: v.alias.trim(),
    display_name: (v.display_name ?? '').trim() || v.alias.trim(),
    description: (v.description ?? '').trim(),
    remote_user: v.remote_user.trim(),
    capabilities: cleanList(v.capabilities),
    record_input: v.record_input ?? false,
    env_allow: cleanList(v.env_allow),
    approval_channels: cleanList(v.approval_channels),
    approvals_required: v.approvals_required ?? 1,
    restriction_notes: (v.restriction_notes ?? '').trim(),
    labels: labelsFromTags(v.labels),
    enabled: v.enabled ?? true,
  };
  if (v.default_duration != null) {
    body.default_duration = Math.round(v.default_duration);
  }
  if (v.max_duration != null) {
    body.max_duration = Math.round(v.max_duration);
  }
  if (v.max_concurrent != null) {
    body.max_concurrent = v.max_concurrent;
  }
  if (v.max_concurrent_per_agent != null) {
    body.max_concurrent_per_agent = v.max_concurrent_per_agent;
  }
  if (v.recording_mode) {
    body.recording_mode = v.recording_mode;
  }
  const retention = (v.retention_class ?? '').trim();
  if (retention !== '') {
    body.retention_class = retention;
  }
  if (version !== undefined) {
    body.version = version;
  }
  return body;
}

export function roleFormValues(r: Role): RoleFormValues {
  return {
    alias: r.alias,
    display_name: r.display_name ?? '',
    description: r.description ?? '',
    remote_user: r.remote_user,
    capabilities: r.capabilities ?? [],
    default_duration: r.default_duration,
    max_duration: r.max_duration,
    max_concurrent: r.max_concurrent ?? null,
    max_concurrent_per_agent: r.max_concurrent_per_agent ?? null,
    recording_mode: r.recording_mode,
    record_input: r.record_input ?? false,
    env_allow: r.env_allow ?? [],
    approval_channels: r.approval_channels ?? [],
    approvals_required: r.approvals_required ?? 1,
    restriction_notes: r.restriction_notes ?? '',
    retention_class: r.retention_class ?? '',
    labels: labelsToTags(r.labels),
    enabled: r.enabled,
  };
}

/** Client-side checks mirroring the server's (internal/inventory/roles.go); the server stays authoritative. */
export function roleFormProblems(v: RoleFormValues): Record<string, string> {
  const problems: Record<string, string> = {};
  const caps = v.capabilities ?? [];
  if (!caps.includes('shell') && !caps.includes('exec') && !caps.includes('file-transfer')) {
    problems.capabilities = 'Include shell, exec or file transfer.';
  }
  if (v.default_duration != null && v.default_duration < 60) {
    problems.default_duration = 'At least 1 minute.';
  }
  if (v.default_duration != null && v.max_duration != null && v.default_duration > v.max_duration) {
    problems.default_duration = 'Must not exceed the maximum duration.';
  }
  if (
    v.max_concurrent != null &&
    v.max_concurrent_per_agent != null &&
    v.max_concurrent_per_agent > v.max_concurrent
  ) {
    problems.max_concurrent_per_agent = 'Must not exceed the total limit.';
  }
  if ((v.approval_channels ?? []).length === 0) {
    problems.approval_channels = 'Choose at least one approval channel.';
  }
  return problems;
}
