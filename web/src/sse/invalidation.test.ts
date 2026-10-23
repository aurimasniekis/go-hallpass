import { describe, expect, it } from 'vitest';

import { keysForEvent, normalizeResource } from './invalidation';

describe('normalizeResource', () => {
  it('normalizes plural, case, separators and aliases', () => {
    expect(normalizeResource('requests')).toBe('request');
    expect(normalizeResource('Access-Sessions')).toBe('access_session');
    expect(normalizeResource('session')).toBe('access_session');
    expect(normalizeResource('activities')).toBe('channel');
    expect(normalizeResource('audit')).toBe('audit_event');
  });
});

describe('keysForEvent', () => {
  it('maps a request event to list, detail, stats and system-status keys', () => {
    expect(keysForEvent({ type: 'request.updated', resource: 'request', resource_id: 'req_1' })).toEqual([
      ['requests'],
      ['request', 'req_1'],
      ['stats'],
      ['system'],
    ]);
  });

  it('maps grant changes to everything that shows grant state', () => {
    const keys = keysForEvent({ type: 'grant.updated', resource: 'grant', resource_id: 'g1' });
    expect(keys).toEqual([
      ['grants'],
      ['grant', 'g1'],
      ['requests'],
      ['access-sessions'],
      ['access-session'],
      ['activities'],
      ['system'],
    ]);
  });

  it('maps activity events (resource "channel", as sent by the backend) to live views', () => {
    const keys = keysForEvent({ type: 'activity.started', resource: 'channel', resource_id: 'ch1' });
    expect(keys).toContainEqual(['activities']);
    expect(keys).toContainEqual(['access-session']);
    expect(keys).toContainEqual(['system']);
  });

  it('maps session events to the session detail subtree', () => {
    const keys = keysForEvent({ type: 'session.updated', resource: 'access_session', resource_id: 's1' });
    expect(keys).toContainEqual(['access-session', 's1']);
  });

  it('omits detail keys when no id is present', () => {
    expect(keysForEvent({ type: 'request.created', resource: 'request' })).toEqual([
      ['requests'],
      ['stats'],
      ['system'],
    ]);
  });

  it('returns null (invalidate all) for reset and unknown resources', () => {
    expect(keysForEvent({ type: 'reset', resource: '' })).toBeNull();
    expect(keysForEvent({ type: 'mystery.updated', resource: 'mystery' })).toBeNull();
  });
});
