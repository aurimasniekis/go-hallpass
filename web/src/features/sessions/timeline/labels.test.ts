import { describe, expect, it } from 'vitest';

import { HIDDEN_FIELDS, timelineFields, timelineLabel, timelineProvenance } from './labels';

describe('timeline labels', () => {
  it('maps known event types and shows unknown ones generically', () => {
    expect(timelineLabel('grant.revoked')).toEqual({ label: 'Grant revoked', tone: 'error' });
    expect(timelineLabel('future.thing')).toEqual({ label: 'future.thing', tone: 'neutral' });
    expect(timelineLabel('x‮y').label).toBe('x<U+202E>y');
  });

  it('flattens data with control characters revealed and nested values JSON-encoded', () => {
    expect(
      timelineFields({ reason: 'bad​reason', exit_status: 0, ok: true, nested: { a: 1 }, none: null }),
    ).toEqual([
      { key: 'exit_status', value: '0' },
      { key: 'nested', value: '{"a":1}' },
      { key: 'none', value: 'null' },
      { key: 'ok', value: 'true' },
      { key: 'reason', value: 'bad<U+200B>reason' },
    ]);
    expect(timelineFields(null)).toEqual([]);
    expect(timelineFields(['a'])).toEqual([]);
  });
});

describe('timeline provenance (HP-REC-006)', () => {
  it('distinguishes captured exec requests from destination-reported commands', () => {
    expect(timelineProvenance('exec.requested')).toBe('captured');
    expect(timelineProvenance('destination.exec')).toBe('destination-audit');
    expect(timelineProvenance('channel.opened')).toBeNull();
    expect(timelineLabel('destination.exec').label).toBe('Destination-reported command');
    expect(HIDDEN_FIELDS.has('verified')).toBe(true);
  });
});
