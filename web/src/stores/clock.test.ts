import { describe, expect, it } from 'vitest';

import { OFFSET_ALPHA, sampleOffset, smoothOffset, type ClockState } from './clock';

const empty: ClockState = { offsetMs: 0, samples: 0, lastSampleAt: null };

describe('sampleOffset', () => {
  it('uses the midpoint of the round trip and of the timestamp resolution', () => {
    // Client sent at 1000, received at 1200 (client mid 1100). Server Date header says 5000 (true time in [5000, 6000)).
    expect(sampleOffset({ serverTimeMs: 5000, sentAt: 1000, receivedAt: 1200, resolutionMs: 1000 })).toBe(
      4400,
    );
  });

  it('handles a server clock that is behind the client', () => {
    expect(sampleOffset({ serverTimeMs: 0, sentAt: 10_000, receivedAt: 10_000, resolutionMs: 0 })).toBe(
      -10_000,
    );
  });

  it('rejects negative, oversized round trips and invalid timestamps', () => {
    expect(sampleOffset({ serverTimeMs: 1, sentAt: 10, receivedAt: 5, resolutionMs: 0 })).toBeNull();
    expect(sampleOffset({ serverTimeMs: 1, sentAt: 0, receivedAt: 60_000, resolutionMs: 0 })).toBeNull();
    expect(sampleOffset({ serverTimeMs: Number.NaN, sentAt: 0, receivedAt: 1, resolutionMs: 0 })).toBeNull();
  });
});

describe('smoothOffset', () => {
  it('takes the first sample as-is', () => {
    expect(smoothOffset(empty, 1234, 1)).toEqual({ offsetMs: 1234, samples: 1, lastSampleAt: 1 });
  });

  it('applies an exponentially weighted moving average', () => {
    const s1 = smoothOffset(empty, 1000, 1);
    const s2 = smoothOffset(s1, 2000, 2);
    expect(s2.offsetMs).toBeCloseTo(1000 + OFFSET_ALPHA * 1000);
    expect(s2.samples).toBe(2);
  });

  it('resets on a large jump (client clock changed)', () => {
    const s1 = smoothOffset(empty, 0, 1);
    expect(smoothOffset(s1, 3_600_000, 2)).toEqual({ offsetMs: 3_600_000, samples: 1, lastSampleAt: 2 });
  });
});
