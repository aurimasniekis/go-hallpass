import { describe, expect, it } from 'vitest';

import {
  bestDurationUnit,
  formatBytes,
  formatDuration,
  formatDurationLong,
  formatRelative,
  parseDuration,
  shortId,
} from './format';

describe('formatDuration', () => {
  it('formats seconds with at most two contiguous units', () => {
    expect(formatDuration(0)).toBe('0s');
    expect(formatDuration(45)).toBe('45s');
    expect(formatDuration(60)).toBe('1m');
    expect(formatDuration(90)).toBe('1m 30s');
    expect(formatDuration(1800)).toBe('30m');
    expect(formatDuration(5400)).toBe('1h 30m');
    expect(formatDuration(3600 * 8)).toBe('8h');
    expect(formatDuration(86_400)).toBe('1d');
    expect(formatDuration(86_400 + 3600)).toBe('1d 1h');
    // 1d 0h 5m: never skips a unit, and never overstates.
    expect(formatDuration(86_400 + 300)).toBe('1d');
    expect(formatDuration(3661, 3)).toBe('1h 1m 1s');
  });

  it('rejects invalid values', () => {
    expect(formatDuration(undefined)).toBe('—');
    expect(formatDuration(null)).toBe('—');
    expect(formatDuration(-5)).toBe('—');
    expect(formatDuration(Number.NaN)).toBe('—');
  });

  it('floors fractional seconds', () => {
    expect(formatDuration(59.9)).toBe('59s');
  });
});

describe('formatDurationLong', () => {
  it('spells out every unit', () => {
    expect(formatDurationLong(5400)).toBe('1 hour 30 minutes');
    expect(formatDurationLong(86_401)).toBe('1 day 1 second');
    expect(formatDurationLong(0)).toBe('0 seconds');
    expect(formatDurationLong(undefined)).toBe('unknown duration');
  });
});

describe('parseDuration', () => {
  it('accepts compact unit strings and bare seconds', () => {
    expect(parseDuration('90m')).toBe(5400);
    expect(parseDuration('1h30m')).toBe(5400);
    expect(parseDuration('1h 30m')).toBe(5400);
    expect(parseDuration('2d')).toBe(172_800);
    expect(parseDuration('45s')).toBe(45);
    expect(parseDuration('120')).toBe(120);
    expect(parseDuration(' 1H ')).toBe(3600);
  });

  it('rejects anything else', () => {
    expect(parseDuration('')).toBeNull();
    expect(parseDuration('1x')).toBeNull();
    expect(parseDuration('h')).toBeNull();
    expect(parseDuration('1h foo')).toBeNull();
    expect(parseDuration('-1h')).toBeNull();
  });

  it('round-trips formatDuration output', () => {
    for (const s of [45, 60, 5400, 86_400, 90_000]) {
      expect(parseDuration(formatDuration(s))).toBe(s);
    }
  });
});

describe('bestDurationUnit', () => {
  it('picks the largest exact unit', () => {
    expect(bestDurationUnit(172_800)).toBe(86_400);
    expect(bestDurationUnit(7200)).toBe(3600);
    expect(bestDurationUnit(5400)).toBe(60);
    expect(bestDurationUnit(0)).toBe(60);
  });
});

describe('formatRelative', () => {
  const now = Date.parse('2026-01-01T12:00:00Z');
  it('describes past and future times', () => {
    expect(formatRelative('2026-01-01T11:59:55Z', now)).toBe('just now');
    expect(formatRelative('2026-01-01T11:59:00Z', now)).toBe('1 min ago');
    expect(formatRelative('2026-01-01T09:00:00Z', now)).toBe('3 h ago');
    expect(formatRelative('2026-01-03T12:00:00Z', now)).toBe('in 2 d');
    expect(formatRelative('nope', now)).toBe('—');
  });
});

describe('formatBytes and shortId', () => {
  it('formats sizes', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KiB');
    expect(formatBytes(50 * 1024 * 1024)).toBe('50 MiB');
    expect(formatBytes(undefined)).toBe('—');
  });

  it('shortens long IDs only', () => {
    expect(shortId('abc')).toBe('abc');
    expect(shortId('0123456789abcdef')).toBe('0123456789…');
    expect(shortId('')).toBe('—');
  });
});
