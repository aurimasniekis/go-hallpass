import type { GitRules, Role } from '../../api/types';

/** Form values of a git access profile. Durations are seconds. */
export interface GitProfileFormValues {
  alias: string;
  description?: string;
  repos: string[];
  write: boolean;
  branches: string[];
  protected_branches: string[];
  tags: string[];
  allow_delete: boolean;
  default_duration: number;
  max_duration: number;
}

export const GIT_PROFILE_DEFAULTS: GitProfileFormValues = {
  alias: '',
  description: '',
  repos: [],
  write: false,
  branches: [],
  protected_branches: ['main', 'master'],
  tags: [],
  allow_delete: false,
  default_duration: 3600,
  max_duration: 8 * 3600,
};

/** Request body for creating or updating a git access profile. */
export function toGitProfileInput(v: GitProfileFormValues) {
  const git: GitRules = { repos: v.repos };
  if (v.write) {
    git.push = {
      branches: v.branches,
      protected_branches: v.protected_branches,
      tags: v.tags,
      allow_delete: v.allow_delete,
    };
  }
  return {
    alias: v.alias.trim(),
    description: (v.description ?? '').trim(),
    capabilities: v.write ? ['git-read', 'git-write'] : ['git-read'],
    git,
    default_duration: v.default_duration,
    max_duration: v.max_duration,
  };
}

export function gitProfileFormValues(r: Role): GitProfileFormValues {
  const push = r.git?.push;
  return {
    alias: r.alias,
    description: r.description ?? '',
    repos: r.git?.repos ?? [],
    write: (r.capabilities ?? []).includes('git-write'),
    branches: push?.branches ?? [],
    protected_branches: push?.protected_branches ?? [],
    tags: push?.tags ?? [],
    allow_delete: push?.allow_delete ?? false,
    default_duration: r.default_duration,
    max_duration: r.max_duration,
  };
}

/** One-line summary of what a profile may push, for tables. */
export function pushSummary(r: Pick<Role, 'capabilities' | 'git'>): string {
  if (!(r.capabilities ?? []).includes('git-write')) {
    return 'Read only';
  }
  const p = r.git?.push ?? {};
  const parts = [`Branches: ${(p.branches ?? []).join(' ') || 'none'}`];
  if ((p.protected_branches ?? []).length > 0) {
    parts.push(`Protected: ${(p.protected_branches ?? []).join(' ')}`);
  }
  if ((p.tags ?? []).length > 0) {
    parts.push(`Tags: ${(p.tags ?? []).join(' ')}`);
  }
  if (p.allow_delete) {
    parts.push('Deletes allowed');
  }
  return parts.join(' · ');
}
