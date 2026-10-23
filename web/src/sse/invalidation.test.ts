import { describe, expect, it } from 'vitest';

import { keysForEvent, normalizeResource } from './invalidation';

describe('normalizeResource', () => {
  it('normalizes plural, case, separators and aliases', () => {
    expect(normalizeResource('requests')).toBe('request');
    expect(normalizeResource('Access-Sessions')).toBe('access_session');
    expect(normalizeResource('session')).toBe('access_session');
    expect(normalizeResource('activities')).toBe('activity');
    expect(normalizeResource('audit')).toBe('audit_event');
  });
});

describe('keysForEvent', () => {
  it('maps a request event to list, detail and stats keys', () => {
    expect(keysForEvent({ type: 'request.updated', resource: 'request', resource_id: 'req_1' })).toEqual([
      ['requests'],
      ['request', 'req_1'],
      ['stats'],
    ]);
  });

  it('maps grant changes to everything that shows grant state', () => {
    const keys = keysForEvent({ type: 'grant.updated', resource: 'grant', resource_id: 'g1' });
    expect(keys).toEqual([['grants'], ['grant', 'g1'], ['requests'], ['access-sessions'], ['activities']]);
  });

  it('omits detail keys when no id is present', () => {
    expect(keysForEvent({ type: 'request.created', resource: 'request' })).toEqual([['requests'], ['stats']]);
  });

  it('returns null (invalidate all) for reset and unknown resources', () => {
    expect(keysForEvent({ type: 'reset', resource: '' })).toBeNull();
    expect(keysForEvent({ type: 'mystery.updated', resource: 'mystery' })).toBeNull();
  });
});
