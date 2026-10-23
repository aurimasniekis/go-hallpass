import { describe, expect, it } from 'vitest';

import { credentialActions, credentialNextStep } from './credentialActions';

const now = Date.parse('2026-06-01T12:00:00Z');

describe('credential lifecycle actions', () => {
  it('pending without a probe: probe and revoke only', () => {
    expect(credentialActions({ state: 'pending' }, now)).toEqual({
      probe: true,
      activate: false,
      forceActivate: false,
      revoke: true,
    });
    expect(credentialNextStep({ state: 'pending' }, now)).toMatch(/Install the authorized_keys line/);
  });

  it('pending with a fresh successful probe can be activated normally', () => {
    const c = { state: 'pending', probe_ok_at: '2026-06-01T11:00:00Z' };
    expect(credentialActions(c, now)).toMatchObject({ activate: true, forceActivate: false });
    expect(credentialNextStep(c, now)).toMatch(/Probe succeeded/);
  });

  it('a stale probe no longer allows normal activation', () => {
    expect(credentialActions({ state: 'pending', probe_ok_at: '2026-05-30T11:00:00Z' }, now).activate).toBe(
      false,
    );
  });

  it('offers forced activation only after a failed probe', () => {
    const c = { state: 'pending', probe_error: 'permission denied (publickey)' };
    expect(credentialActions(c, now)).toMatchObject({ activate: false, forceActivate: true });
    expect(credentialNextStep(c, now)).toMatch(/last probe failed/);
  });

  it('ended credentials offer nothing', () => {
    for (const state of ['retired', 'revoked']) {
      expect(credentialActions({ state }, now)).toEqual({
        probe: false,
        activate: false,
        forceActivate: false,
        revoke: false,
      });
    }
    expect(credentialActions({ state: 'active' }, now)).toMatchObject({
      probe: true,
      activate: false,
      revoke: true,
    });
  });
});
