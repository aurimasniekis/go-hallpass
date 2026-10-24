import { describe, expect, it } from 'vitest';

import type { Role } from '../../api/types';
import { GIT_PROFILE_DEFAULTS, gitProfileFormValues, pushSummary, toGitProfileInput } from './gitForm';
import { presetFor } from './presets';

describe('git profile form', () => {
  it('sends read-only profiles without push rules', () => {
    const body = toGitProfileInput({ ...GIT_PROFILE_DEFAULTS, alias: ' acme-read ', repos: ['acme/*'] });
    expect(body).toEqual({
      alias: 'acme-read',
      description: '',
      capabilities: ['git-read'],
      git: { repos: ['acme/*'] },
      default_duration: 3600,
      max_duration: 28800,
    });
  });

  it('sends push rules with git-write and round-trips them', () => {
    const values = {
      ...GIT_PROFILE_DEFAULTS,
      alias: 'acme-push',
      repos: ['acme/{api,web}'],
      write: true,
      branches: ['agent/**'],
      tags: ['v*-rc.*'],
      allow_delete: true,
    };
    const body = toGitProfileInput(values);
    expect(body.capabilities).toEqual(['git-read', 'git-write']);
    expect(body.git.push).toEqual({
      branches: ['agent/**'],
      protected_branches: ['main', 'master'],
      tags: ['v*-rc.*'],
      allow_delete: true,
      allow_force_push: false,
    });
    const role = {
      ...body,
      id: 'rol_1',
      server_id: 's',
      remote_user: 'git',
      recording_mode: 'mandatory',
      enabled: true,
      version: 3,
    } as Role;
    expect(gitProfileFormValues(role)).toEqual({ ...values, description: '' });
    expect(pushSummary(role)).toBe(
      'Branches: agent/** · Protected: main master · Tags: v*-rc.* · Deletes allowed',
    );
    expect(pushSummary({ capabilities: ['git-read'], git: { repos: ['x'] } })).toBe('Read only');
  });

  it('recognizes preset hosts', () => {
    expect(presetFor('GitHub.com')?.name).toBe('GitHub');
    expect(presetFor('git.example.com')).toBeUndefined();
  });
});
