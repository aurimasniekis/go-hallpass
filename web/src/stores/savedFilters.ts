import { Store, useSelector } from '@tanstack/react-store';

import { readPersisted, writePersisted } from './persist';

/**
 * Saved table filters (HP-UI-008), persisted per browser as a UI preference. Filters hold only query
 * parameters (states, IDs, action names) — never tokens or response data.
 */
export type FilterValues = Record<string, string>;

export interface SavedFilter {
  name: string;
  filters: FilterValues;
}

export const SAVED_FILTERS_STORAGE_KEY = 'hallpass.savedFilters';
const MAX_PER_TABLE = 20;

type SavedFiltersState = Record<string, SavedFilter[]>;

export function parseSavedFilters(raw: string | null): SavedFiltersState {
  if (!raw) {
    return {};
  }
  try {
    const value = JSON.parse(raw) as unknown;
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return {};
    }
    const out: SavedFiltersState = {};
    for (const [table, list] of Object.entries(value as Record<string, unknown>)) {
      if (!Array.isArray(list)) {
        continue;
      }
      out[table] = list
        .filter((f: unknown): f is SavedFilter => {
          if (typeof f !== 'object' || f === null) {
            return false;
          }
          const c = f as { name?: unknown; filters?: unknown };
          return typeof c.name === 'string' && typeof c.filters === 'object' && c.filters !== null;
        })
        .map((f) => ({
          name: f.name.slice(0, 64),
          filters: Object.fromEntries(
            Object.entries(f.filters).filter((e): e is [string, string] => typeof e[1] === 'string'),
          ),
        }))
        .slice(0, MAX_PER_TABLE);
    }
    return out;
  } catch {
    return {};
  }
}

export const savedFiltersStore = new Store<SavedFiltersState>(
  parseSavedFilters(readPersisted(SAVED_FILTERS_STORAGE_KEY)),
);

function persist(state: SavedFiltersState): void {
  writePersisted(SAVED_FILTERS_STORAGE_KEY, JSON.stringify(state));
}

/** Saves (or replaces, by name) a filter for `table`. Empty values are dropped. */
export function saveFilter(table: string, name: string, filters: FilterValues): void {
  const clean = Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== ''));
  savedFiltersStore.setState((s) => {
    const list = (s[table] ?? []).filter((f) => f.name !== name);
    const next = {
      ...s,
      [table]: [...list, { name: name.slice(0, 64), filters: clean }].slice(-MAX_PER_TABLE),
    };
    persist(next);
    return next;
  });
}

export function deleteFilter(table: string, name: string): void {
  savedFiltersStore.setState((s) => {
    const next = { ...s, [table]: (s[table] ?? []).filter((f) => f.name !== name) };
    persist(next);
    return next;
  });
}

const EMPTY: SavedFilter[] = [];

export function useSavedFilters(table: string): SavedFilter[] {
  return useSelector(savedFiltersStore, (s) => s[table] ?? EMPTY);
}
