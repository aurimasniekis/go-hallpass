import { describe, expect, it } from 'vitest';

import type { Role } from '../../api/types';
import { apiProfileDefaults, apiProfileFormValues, ruleSummary, toApiProfileInput } from './apiForm';
import { API_PRESETS, presetForHosts } from './presets';

describe('API profile form', () => {
  it('drops empty lists and keeps the rule order', () => {
    const values = apiProfileDefaults([
      { effect: 'allow', methods: ['GET'] },
      { effect: 'deny', paths: ['/user/keys'] },
    ]);
    values.alias = ' read ';
    values.rules.push({
      effect: 'allow',
      methods: ['POST'],
      paths: [' /graphql ', ''],
      graphql: ['query'],
      hosts: [],
    });
    expect(toApiProfileInput(values)).toEqual({
      alias: 'read',
      description: '',
      capabilities: ['api'],
      api: {
        rules: [
          { effect: 'allow', methods: ['GET'] },
          { effect: 'deny', paths: ['/user/keys'] },
          { effect: 'allow', methods: ['POST'], paths: ['/graphql'], graphql: ['query'] },
        ],
      },
      approvals_required: 1,
      default_duration: 3600,
      max_duration: 8 * 3600,
    });
  });

  it('round-trips a role', () => {
    const role = {
      id: 'rol_1',
      server_id: 'srv_1',
      alias: 'issues',
      remote_user: 'api',
      capabilities: ['api'],
      default_duration: 600,
      max_duration: 3600,
      recording_mode: 'mandatory',
      enabled: true,
      version: 3,
      approvals_required: 2,
      api: { rules: [{ effect: 'allow', methods: ['POST'], paths: ['/repos/acme/*/issues/**'] }] },
    } as Role;
    const v = apiProfileFormValues(role);
    expect(v.rules[0]).toEqual({
      effect: 'allow',
      methods: ['POST'],
      hosts: [],
      paths: ['/repos/acme/*/issues/**'],
      graphql: [],
    });
    expect(toApiProfileInput(v).api.rules).toEqual(role.api?.rules);
  });

  it('summarizes rules', () => {
    expect(ruleSummary({ effect: 'allow' })).toBe('allow any method any path');
    expect(ruleSummary({ effect: 'allow', methods: ['POST'], paths: ['/graphql'], graphql: ['query'] })).toBe(
      'allow POST /graphql (GraphQL query)',
    );
  });

  it('recognizes presets by host', () => {
    expect(presetForHosts(['api.github.com'])?.id).toBe('github');
    expect(presetForHosts(['*.googleapis.com'])?.id).toBe('google');
    expect(presetForHosts(['api.example.com'])).toBeUndefined();
    for (const p of API_PRESETS) {
      for (const t of p.templates) {
        expect(t.rules.some((r) => r.effect === 'allow')).toBe(true);
      }
    }
  });
});
