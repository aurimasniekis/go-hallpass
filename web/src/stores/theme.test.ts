import { afterEach, describe, expect, it, vi } from 'vitest';

import { parseThemeMode, resolveTheme, setThemeMode, THEME_STORAGE_KEY, themeStore } from './theme';

describe('theme store', () => {
  afterEach(() => {
    window.localStorage.clear();
  });

  it('parses only known modes and defaults to system', () => {
    expect(parseThemeMode('dark')).toBe('dark');
    expect(parseThemeMode('light')).toBe('light');
    expect(parseThemeMode('<script>')).toBe('system');
    expect(parseThemeMode(null)).toBe('system');
  });

  it('resolves system mode from the OS preference', () => {
    expect(resolveTheme({ mode: 'system', systemPrefersDark: true })).toBe('dark');
    expect(resolveTheme({ mode: 'system', systemPrefersDark: false })).toBe('light');
    expect(resolveTheme({ mode: 'light', systemPrefersDark: true })).toBe('light');
  });

  it('persists the chosen mode', () => {
    setThemeMode('dark');
    expect(themeStore.state.mode).toBe('dark');
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark');
  });

  it('keeps working when localStorage throws', () => {
    const spy = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError');
    });
    expect(() => {
      setThemeMode('light');
    }).not.toThrow();
    expect(themeStore.state.mode).toBe('light');
    spy.mockRestore();
  });
});
