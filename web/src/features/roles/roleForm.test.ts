import { describe, expect, it } from 'vitest';

import type { Role } from '../../api/types';
import { ROLE_DEFAULTS, roleFormProblems, roleFormValues, toRoleInput } from './roleForm';

const role: Role = {
  id: 'r1',
  server_id: 's1',
  alias: 'deploy',
  display_name: 'Deploy',
  remote_user: 'deploy',
  capabilities: ['exec'],
  default_duration: 1800,
  max_duration: 21600,
  max_concurrent: 10,
  max_concurrent_per_agent: 2,
  recording_mode: 'mandatory',
  record_input: false,
  approval_channels: ['web'],
  retention_class: 'default',
  labels: { tier: 'app' },
  enabled: true,
  version: 4,
};

describe('role form mapping', () => {
  it('sends durations as integer seconds and keeps only spec fields', () => {
    const body = toRoleInput({
      ...ROLE_DEFAULTS,
      alias: 'ops',
      remote_user: 'ops',
      default_duration: 5400.4,
    });
    expect(body.default_duration).toBe(5400);
    expect(body.max_duration).toBe(21600);
    expect(body.display_name).toBe('ops');
    expect(body).not.toHaveProperty('version');
    expect(Object.keys(body).sort()).toEqual(
      [
        'alias',
        'approval_channels',
        'approvals_required',
        'capabilities',
        'default_duration',
        'description',
        'display_name',
        'enabled',
        'env_allow',
        'labels',
        'max_concurrent',
        'max_concurrent_per_agent',
        'max_duration',
        'record_input',
        'recording_mode',
        'remote_user',
        'restriction_notes',
        'retention_class',
      ].sort(),
    );
  });

  it('round-trips a role and carries the version on edit', () => {
    const body = toRoleInput(roleFormValues(role), role.version);
    expect(body).toMatchObject({
      version: 4,
      alias: 'deploy',
      capabilities: ['exec'],
      default_duration: 1800,
      max_duration: 21600,
      labels: { tier: 'app' },
      approval_channels: ['web'],
    });
  });

  it('omits unset numbers so the server keeps its defaults', () => {
    const body = toRoleInput({ alias: 'a', remote_user: 'u', default_duration: null, max_concurrent: null });
    expect(body).not.toHaveProperty('default_duration');
    expect(body).not.toHaveProperty('max_concurrent');
  });

  it('flags the same problems the server would', () => {
    expect(
      roleFormProblems({
        alias: 'a',
        remote_user: 'u',
        capabilities: ['pty'],
        default_duration: 30,
        max_duration: 20,
        max_concurrent: 1,
        max_concurrent_per_agent: 2,
        approval_channels: [],
      }),
    ).toEqual({
      capabilities: 'Include shell, exec or file transfer.',
      default_duration: 'Must not exceed the maximum duration.',
      max_concurrent_per_agent: 'Must not exceed the total limit.',
      approval_channels: 'Choose at least one approval channel.',
    });
    expect(roleFormProblems(ROLE_DEFAULTS)).toEqual({});
  });
});
