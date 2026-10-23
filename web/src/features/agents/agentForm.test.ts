import { describe, expect, it } from 'vitest';

import { LabelFormatError } from '../servers/formUtils';
import { agentFormValues, toAgentCreate, toAgentPatch } from './agentForm';

describe('agent form mapping', () => {
  it('builds a create body with cleaned lists, parsed labels and one key per line', () => {
    expect(
      toAgentCreate({
        name: '  ci-runner ',
        description: ' builds ',
        source_cidrs: ['10.0.0.0/8', ' 10.0.0.0/8', ''],
        groups: ['ci'],
        labels: ['env=prod', 'team=ops'],
        public_keys: 'ssh-ed25519 AAAA one\n\n# comment\nssh-ed25519 BBBB two\n',
      }),
    ).toEqual({
      name: 'ci-runner',
      description: 'builds',
      enabled: true,
      source_cidrs: ['10.0.0.0/8'],
      groups: ['ci'],
      labels: { env: 'prod', team: 'ops' },
      public_keys: ['ssh-ed25519 AAAA one', 'ssh-ed25519 BBBB two'],
    });
  });

  it('omits public_keys when none are given and keeps enabled=false', () => {
    const body = toAgentCreate({ name: 'a', enabled: false });
    expect(body).not.toHaveProperty('public_keys');
    expect(body.enabled).toBe(false);
  });

  it('rejects malformed labels before sending anything', () => {
    expect(() => toAgentCreate({ name: 'a', labels: ['novalue'] })).toThrow(LabelFormatError);
  });

  it('builds a patch carrying the version and only spec fields', () => {
    const patch = toAgentPatch({ name: 'a', enabled: false, public_keys: 'x', labels: [] }, 7);
    expect(patch).toEqual({
      version: 7,
      name: 'a',
      description: '',
      source_cidrs: [],
      groups: [],
      labels: {},
    });
  });

  it('round-trips an agent into form values', () => {
    expect(
      agentFormValues({
        id: 'a1',
        name: 'n',
        description: 'd',
        enabled: true,
        source_cidrs: null,
        groups: ['g'],
        labels: { b: '2', a: '1' },
        version: 1,
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      }),
    ).toEqual({
      name: 'n',
      description: 'd',
      enabled: true,
      source_cidrs: [],
      groups: ['g'],
      labels: ['a=1', 'b=2'],
    });
  });
});
