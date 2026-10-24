import { describe, expect, it } from 'vitest';

import {
  accessBodies,
  effectiveStep,
  focusCredential,
  installCommand,
  needsOnboarding,
  newAccessForm,
  nextStep,
  parseStep,
  prepareSshDirCommand,
  previousStep,
  resumeStep,
  roleLogin,
  stepStates,
  targetsServer,
  type WizardFacts,
} from './model';

const server = { id: 'srv_1', active_host_identities: 0 };
const roles = [
  { id: 'rol_1', enabled: true },
  { id: 'rol_2', enabled: true },
];

describe('onboarding steps', () => {
  it('starts at the server step and resumes at the first unfinished step', () => {
    expect(resumeStep({ server: null })).toBe('server');
    expect(effectiveStep('credentials', { server: null })).toBe('server');
    const noIdentity: WizardFacts = { server, roles: [] };
    expect(resumeStep(noIdentity)).toBe('identity');
    const pinned: WizardFacts = { server: { ...server, active_host_identities: 1 }, roles: [] };
    expect(resumeStep(pinned)).toBe('roles');
    const withRoles: WizardFacts = { ...pinned, roles, logins: { rol_1: 'active', rol_2: 'pending' } };
    expect(resumeStep(withRoles)).toBe('credentials');
    const allLogins: WizardFacts = { ...withRoles, logins: { rol_1: 'active', rol_2: 'certificate' } };
    expect(resumeStep(allLogins)).toBe('access');
    expect(resumeStep({ ...allLogins, accessRules: [{}] })).toBe('done');
    expect(resumeStep({ ...allLogins, accessSkipped: true })).toBe('done');
  });

  it('opens a requested step only when its prerequisites exist', () => {
    const facts: WizardFacts = { server, roles: [] };
    expect(effectiveStep('roles', facts)).toBe('roles');
    expect(effectiveStep('credentials', facts)).toBe('identity');
    expect(effectiveStep('access', { server, roles })).toBe('access');
    expect(effectiveStep(undefined, { server, roles })).toBe('identity');
    const states = stepStates({ server, roles: [] });
    expect(states.map((s) => [s.key, s.available, s.done])).toEqual([
      ['server', true, true],
      ['identity', true, false],
      ['roles', true, false],
      ['credentials', false, false],
      ['access', false, false],
      ['done', true, false],
    ]);
  });

  it('counts a host CA binding or a confirmed key as a verified identity', () => {
    expect(stepStates({ server: { ...server, host_ca_id: 'hca_1' } })[1]?.done).toBe(true);
    // Listed identities win over the server's counter (they are fresher after a confirm).
    expect(stepStates({ server, identities: [{ state: 'pending' }] })[1]?.done).toBe(false);
    expect(stepStates({ server, identities: [{ state: 'active' }] })[1]?.done).toBe(true);
  });

  it('ignores disabled roles for the credentials step', () => {
    const facts: WizardFacts = {
      server,
      roles: [...roles, { id: 'rol_3', enabled: false }],
      logins: { rol_1: 'active', rol_2: 'active', rol_3: 'none' },
    };
    expect(stepStates(facts)[3]?.done).toBe(true);
  });

  it('navigates and parses steps', () => {
    expect(nextStep('server')).toBe('identity');
    expect(nextStep('done')).toBe('done');
    expect(previousStep('server')).toBe('server');
    expect(previousStep('access')).toBe('credentials');
    expect(parseStep('roles')).toBe('roles');
    expect(parseStep('nope')).toBeUndefined();
    expect(parseStep(3)).toBeUndefined();
  });

  it('offers to resume onboarding from the server page while basics are missing', () => {
    expect(needsOnboarding(server, [])).toBe(true);
    expect(needsOnboarding({ ...server, active_host_identities: 1 }, [])).toBe(true);
    expect(needsOnboarding({ ...server, active_host_identities: 1 }, [{}])).toBe(false);
    expect(needsOnboarding({ ...server, host_ca_id: 'hca' }, undefined)).toBe(false);
  });
});

describe('role login state', () => {
  it('derives the login state from credentials', () => {
    expect(roleLogin(undefined)).toBe('unknown');
    expect(roleLogin([])).toBe('none');
    expect(roleLogin([{ state: 'pending' }])).toBe('pending');
    expect(roleLogin([{ state: 'revoked' }, { state: 'retiring' }])).toBe('active');
    expect(roleLogin([{ state: 'pending' }], true)).toBe('certificate');
    expect(roleLogin(undefined, true)).toBe('certificate');
  });

  it('focuses the newest pending credential', () => {
    const creds = [
      { id: 'a', state: 'pending', created_at: '2026-01-01T00:00:00Z' },
      { id: 'b', state: 'pending', created_at: '2026-01-02T00:00:00Z' },
      { id: 'c', state: 'active', created_at: '2026-01-03T00:00:00Z' },
    ];
    expect(focusCredential(creds)?.id).toBe('b');
    expect(focusCredential<(typeof creds)[number]>([])).toBeUndefined();
  });

  it('builds a safely quoted install command', () => {
    const line = 'from="10.0.0.1",restrict ssh-ed25519 AAAA hallpass';
    expect(installCommand(line, 'deploy')).toBe(
      `echo 'from="10.0.0.1",restrict ssh-ed25519 AAAA hallpass' | sudo tee -a ~deploy/.ssh/authorized_keys`,
    );
    expect(installCommand("x' ; rm -rf / ; '", 'deploy')).toBe(
      `echo 'x'\\'' ; rm -rf / ; '\\''' | sudo tee -a ~deploy/.ssh/authorized_keys`,
    );
    expect(installCommand('k', 'bad user')).toContain('~<remote user>/.ssh/authorized_keys');
    expect(prepareSshDirCommand('deploy')).toBe('sudo install -d -m 700 -o deploy ~deploy/.ssh');
  });
});

describe('access step bodies', () => {
  const srv = { id: 'srv_1', alias: 'Web 1' };

  it('reports missing input instead of building bodies', () => {
    const r = accessBodies(newAccessForm([]), srv);
    expect(r.rule).toBeNull();
    expect(r.errors).toEqual([
      'Choose at least one agent group.',
      'Choose at least one role.',
      'Choose at least one approver (an operator or an operator group).',
    ]);
  });

  it('builds a requestable rule and an approver rule scoped to the server and roles', () => {
    const form = {
      ...newAccessForm(['rol_1']),
      agentGroups: ['sre', ' sre ', 'ci'],
      maxDuration: 3600,
      approverOperatorIds: ['opr_1'],
    };
    const r = accessBodies(form, srv);
    expect(r.errors).toEqual([]);
    expect(r.rule).toEqual({
      name: 'web-1-request',
      description: 'Created by the onboarding wizard for Web 1.',
      effect: 'allow',
      level: 'requestable',
      subjects: { agent_groups: ['sre', 'ci'] },
      targets: { servers: ['srv_1'] },
      roles: { ids: ['rol_1'] },
      require_reason: true,
      enabled: true,
      max_duration: 3600,
    });
    expect(r.approver).toEqual({
      name: 'web-1-approvers',
      description: 'Created by the onboarding wizard for Web 1.',
      operators: { operators: ['opr_1'] },
      targets: { servers: ['srv_1'] },
      roles: { ids: ['rol_1'] },
      enabled: true,
    });
  });

  it('validates auto-approve limits', () => {
    const base = {
      ...newAccessForm(['rol_1']),
      agentGroups: ['sre'],
      approver: false,
      level: 'auto_approve' as const,
    };
    expect(accessBodies({ ...base, autoMaxDuration: 0 }, srv).errors).toEqual([
      'Auto-approval needs a limit of at least 1 minute.',
    ]);
    expect(accessBodies({ ...base, autoMaxDuration: 7200, maxDuration: 3600 }, srv).errors).toEqual([
      'The auto-approval limit cannot exceed the maximum duration.',
    ]);
    const ok = accessBodies({ ...base, autoMaxDuration: 1800 }, srv);
    expect(ok.rule?.auto_max_duration).toBe(1800);
    expect(ok.rule?.name).toBe('web-1-auto');
    expect(ok.approver).toBeNull();
  });

  it('recognizes rules that target the server', () => {
    const srv = { id: 'srv_1', groups: ['prod-web'], labels: { env: 'prod', tier: 'web' } };
    expect(targetsServer({ targets: { servers: ['srv_1'] } }, srv)).toBe(true);
    expect(targetsServer({ targets: { all: true } }, srv)).toBe(true);
    expect(targetsServer({ targets: { servers: ['srv_2'] } }, srv)).toBe(false);
    expect(targetsServer({ targets: {} }, srv)).toBe(false);
    expect(targetsServer({ targets: { server_groups: ['prod-db', 'prod-web'] } }, srv)).toBe(true);
    expect(targetsServer({ targets: { server_groups: ['prod-db'] } }, srv)).toBe(false);
    expect(targetsServer({ targets: { server_labels: { matchLabels: { env: 'prod' } } } }, srv)).toBe(true);
    expect(targetsServer({ targets: { server_labels: { matchLabels: { env: 'dev' } } } }, srv)).toBe(false);
    // An empty label selector matches nothing, like on the server.
    expect(targetsServer({ targets: { server_labels: {} } }, srv)).toBe(false);
    const expr = (operator: string, values?: string[]) => ({
      targets: {
        server_labels: { matchExpressions: [{ key: 'tier', operator, ...(values ? { values } : {}) }] },
      },
    });
    expect(targetsServer(expr('In', ['web', 'db']), srv)).toBe(true);
    expect(targetsServer(expr('NotIn', ['web']), srv)).toBe(false);
    expect(targetsServer(expr('Exists'), srv)).toBe(true);
    expect(targetsServer(expr('DoesNotExist'), srv)).toBe(false);
    expect(targetsServer(expr('Bogus'), srv)).toBe(false);
  });
});
