import { describe, expect, it } from 'vitest';

import { approveBody, choiceKey, parseChoiceKey } from './decision';
import { searchToFilters, validateRequestSearch } from './search';

describe('request search validation', () => {
  it('keeps known states and ID-shaped values only', () => {
    expect(validateRequestSearch({ state: 'pending', agent_id: 'agt_1', server_id: 'srv-2' })).toEqual({
      state: 'pending',
      agent_id: 'agt_1',
      server_id: 'srv-2',
    });
    expect(validateRequestSearch({ state: 'bogus', agent_id: 'a b', server_id: 5 })).toEqual({});
    expect(validateRequestSearch({ agent_id: 'x'.repeat(65) })).toEqual({});
  });

  it('serializes search into saved-filter values', () => {
    expect(searchToFilters({ state: 'denied', agent_id: 'a1' })).toEqual({ state: 'denied', agent_id: 'a1' });
  });
});

describe('approve body', () => {
  it('uses 0 for the requested duration and trims comments', () => {
    expect(approveBody({ kind: 'requested' }, null, '  ')).toEqual({ duration: 0 });
    expect(approveBody({ kind: 'preset', seconds: 3600 }, null, ' ok ')).toEqual({
      duration: 3600,
      comment: 'ok',
    });
  });

  it('requires a custom duration of at least a minute', () => {
    expect(approveBody({ kind: 'custom' }, null, '')).toBeNull();
    expect(approveBody({ kind: 'custom' }, 30, '')).toBeNull();
    expect(approveBody({ kind: 'custom' }, 5400, '')).toEqual({ duration: 5400 });
  });

  it('round-trips choice keys', () => {
    for (const c of [{ kind: 'requested' }, { kind: 'custom' }, { kind: 'preset', seconds: 900 }] as const) {
      expect(parseChoiceKey(choiceKey(c))).toEqual(c);
    }
  });
});
