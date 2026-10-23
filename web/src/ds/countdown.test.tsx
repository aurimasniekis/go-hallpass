import { act, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { formatRemaining, remainingMs, serverNow } from './countdownMath';
import { Countdown } from './Countdown';

describe('countdown math', () => {
  it('corrects client time by the server offset', () => {
    expect(serverNow(1_000, 250)).toBe(1_250);
    // Deadline at server t=10s. Client clock reads 5s but is 2s behind the server.
    expect(remainingMs(10_000, 5_000, 2_000)).toBe(3_000);
    // Same deadline, client 2s ahead of the server.
    expect(remainingMs(10_000, 5_000, -2_000)).toBe(7_000);
  });

  it('parses RFC 3339 deadlines and rejects garbage', () => {
    const now = Date.parse('2026-01-01T00:00:00Z');
    expect(remainingMs('2026-01-01T00:01:00Z', now, 0)).toBe(60_000);
    expect(remainingMs('not a date', now, 0)).toBeNull();
  });

  it('formats remaining time, rounding down', () => {
    expect(formatRemaining(59_999)).toBe('0m 59s');
    expect(formatRemaining(61_000)).toBe('1m 01s');
    expect(formatRemaining(3_600_000 + 2 * 60_000 + 3_000)).toBe('1h 02m 03s');
    expect(formatRemaining(2 * 86_400_000 + 3_600_000)).toBe('2d 01h 00m');
    expect(formatRemaining(999)).toBe('0m 00s');
    expect(formatRemaining(0)).toBeNull();
    expect(formatRemaining(-5)).toBeNull();
  });
});

describe('<Countdown>', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('ticks down using the server offset and shows expiry', () => {
    // Server is 30s ahead of the client: only 30s remain of a deadline 60s ahead of the client clock.
    render(<Countdown deadline="2026-01-01T00:01:00Z" offsetMs={30_000} />);
    expect(screen.getByRole('timer')).toHaveTextContent('0m 30s');
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(screen.getByRole('timer')).toHaveTextContent('0m 20s');
    act(() => {
      vi.advanceTimersByTime(25_000);
    });
    expect(screen.getByRole('timer')).toHaveTextContent('Expired');
  });
});
