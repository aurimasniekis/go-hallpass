import { Store, useSelector } from '@tanstack/react-store';

import type { ResolvedTheme } from '../ds/theme/tokens';
import { readPersisted, writePersisted } from './persist';

export type ThemeMode = 'light' | 'dark' | 'system';

export interface ThemeState {
  mode: ThemeMode;
  systemPrefersDark: boolean;
}

export const THEME_STORAGE_KEY = 'hallpass.theme';
const DARK_QUERY = '(prefers-color-scheme: dark)';

export function parseThemeMode(value: unknown): ThemeMode {
  return value === 'light' || value === 'dark' || value === 'system' ? value : 'system';
}

function systemPrefersDark(): boolean {
  try {
    return typeof window.matchMedia === 'function' && window.matchMedia(DARK_QUERY).matches;
  } catch {
    return false;
  }
}

export function resolveTheme(state: ThemeState): ResolvedTheme {
  if (state.mode === 'system') {
    return state.systemPrefersDark ? 'dark' : 'light';
  }
  return state.mode;
}

export const themeStore = new Store<ThemeState>({
  mode: parseThemeMode(readPersisted(THEME_STORAGE_KEY)),
  systemPrefersDark: systemPrefersDark(),
});

export function setThemeMode(mode: ThemeMode): void {
  themeStore.setState((s) => ({ ...s, mode }));
  writePersisted(THEME_STORAGE_KEY, mode);
}

/** Follows OS theme changes while mode is `system`. Returns an unsubscribe function. */
export function watchSystemTheme(): () => void {
  if (typeof window.matchMedia !== 'function') {
    return () => undefined;
  }
  const mql = window.matchMedia(DARK_QUERY);
  const onChange = (e: MediaQueryListEvent) => {
    themeStore.setState((s) => ({ ...s, systemPrefersDark: e.matches }));
  };
  mql.addEventListener('change', onChange);
  themeStore.setState((s) => ({ ...s, systemPrefersDark: mql.matches }));
  return () => {
    mql.removeEventListener('change', onChange);
  };
}

export function useThemeMode(): ThemeMode {
  return useSelector(themeStore, (s) => s.mode);
}

export function useResolvedTheme(): ResolvedTheme {
  return useSelector(themeStore, resolveTheme);
}
