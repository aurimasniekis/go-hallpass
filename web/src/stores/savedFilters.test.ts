import { beforeEach, describe, expect, it } from 'vitest';

import {
  deleteFilter,
  parseSavedFilters,
  SAVED_FILTERS_STORAGE_KEY,
  saveFilter,
  savedFiltersStore,
} from './savedFilters';

describe('saved filters', () => {
  beforeEach(() => {
    savedFiltersStore.setState(() => ({}));
    window.localStorage.clear();
  });

  it('saves, replaces by name, drops empty values and persists', () => {
    saveFilter('requests', 'Pending', { state: 'pending', agent_id: '' });
    saveFilter('requests', 'Pending', { state: 'pending', server_id: 's1' });
    expect(savedFiltersStore.state.requests).toEqual([
      { name: 'Pending', filters: { state: 'pending', server_id: 's1' } },
    ]);
    expect(parseSavedFilters(window.localStorage.getItem(SAVED_FILTERS_STORAGE_KEY))).toEqual(
      savedFiltersStore.state,
    );
    deleteFilter('requests', 'Pending');
    expect(savedFiltersStore.state.requests).toEqual([]);
  });

  it('ignores malformed persisted data', () => {
    expect(parseSavedFilters('not json')).toEqual({});
    expect(parseSavedFilters('[1]')).toEqual({});
    expect(
      parseSavedFilters(
        JSON.stringify({ audit: [{ name: 'x', filters: { a: 'b', n: 1 } }, { bad: true }], y: 3 }),
      ),
    ).toEqual({ audit: [{ name: 'x', filters: { a: 'b' } }] });
  });
});
