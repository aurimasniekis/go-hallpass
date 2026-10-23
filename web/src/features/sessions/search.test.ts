import { describe, expect, it } from 'vitest';

import { validateSessionsSearch } from './search';

describe('validateSessionsSearch', () => {
  it('keeps valid filters for the active tab', () => {
    expect(validateSessionsSearch({ state: 'open', agent_id: 'ag_1', junk: 'x' })).toEqual({
      state: 'open',
      agent_id: 'ag_1',
    });
    expect(validateSessionsSearch({ tab: 'grants', state: 'revoked', server_id: 'srv-1' })).toEqual({
      tab: 'grants',
      state: 'revoked',
      server_id: 'srv-1',
    });
  });

  it('drops states of the other tab and malformed IDs', () => {
    expect(validateSessionsSearch({ tab: 'grants', state: 'open' })).toEqual({ tab: 'grants' });
    expect(validateSessionsSearch({ tab: 'nope', state: 'revoked' })).toEqual({});
    expect(validateSessionsSearch({ agent_id: '../x', server_id: 5 })).toEqual({});
  });
});
