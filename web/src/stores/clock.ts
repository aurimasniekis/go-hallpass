import { Store, useSelector } from '@tanstack/react-store';

/**
 * Server clock offset (docs/PLAN.md §14.4, HP-UI-011).
 *
 * `offsetMs` is `serverTime - clientTime`. Countdowns compute "server now" as `Date.now() + offsetMs`
 * so that a skewed operator workstation clock does not shorten or lengthen displayed grant lifetimes.
 *
 * Samples currently come from the HTTP `Date` header of API responses (1 s resolution, so each
 * sample is accurate to roughly ±(0.5 s + RTT/2)). PLAN also names `GET /system/time` as a precise
 * source; it is not implemented in the backend yet, so only header samples are used.
 */
export interface ClockState {
  offsetMs: number;
  samples: number;
  lastSampleAt: number | null;
}

export interface ClockSample {
  /** Server time reported by the response, in ms since epoch. */
  serverTimeMs: number;
  /** Client time when the request was sent. */
  sentAt: number;
  /** Client time when the response headers arrived. */
  receivedAt: number;
  /** Resolution of `serverTimeMs` (1000 for the HTTP Date header, which truncates to whole seconds). */
  resolutionMs: number;
}

/** Smoothing factor for the exponentially weighted moving average. */
export const OFFSET_ALPHA = 0.2;
/** A sample that disagrees with the current estimate by more than this resets the estimate (clock jump). */
export const OFFSET_RESET_THRESHOLD_MS = 30_000;
/** Samples over a round trip longer than this are too imprecise to use. */
export const MAX_SAMPLE_RTT_MS = 10_000;

/** Offset estimated from one request/response exchange, or null when the sample is unusable. */
export function sampleOffset(sample: ClockSample): number | null {
  const rtt = sample.receivedAt - sample.sentAt;
  if (!Number.isFinite(sample.serverTimeMs) || rtt < 0 || rtt > MAX_SAMPLE_RTT_MS) {
    return null;
  }
  // A truncated timestamp lies anywhere in [t, t + resolution); use the midpoint.
  const serverMid = sample.serverTimeMs + sample.resolutionMs / 2;
  const clientMid = sample.sentAt + rtt / 2;
  return serverMid - clientMid;
}

/** Folds a new sample into the running estimate. */
export function smoothOffset(current: ClockState, sampleOffsetMs: number, at: number): ClockState {
  if (current.samples === 0 || Math.abs(sampleOffsetMs - current.offsetMs) > OFFSET_RESET_THRESHOLD_MS) {
    return { offsetMs: sampleOffsetMs, samples: 1, lastSampleAt: at };
  }
  return {
    offsetMs: current.offsetMs + OFFSET_ALPHA * (sampleOffsetMs - current.offsetMs),
    samples: current.samples + 1,
    lastSampleAt: at,
  };
}

export const clockStore = new Store<ClockState>({ offsetMs: 0, samples: 0, lastSampleAt: null });

export function recordClockSample(sample: ClockSample): void {
  const offset = sampleOffset(sample);
  if (offset === null) {
    return;
  }
  clockStore.setState((s) => smoothOffset(s, offset, sample.receivedAt));
}

export function useServerClockOffset(): number {
  return useSelector(clockStore, (s) => s.offsetMs);
}
