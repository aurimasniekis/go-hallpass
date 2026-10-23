import { Store, useSelector } from '@tanstack/react-store';

/**
 * Live-event connection status (docs/PLAN.md §14.4, HP-UI-007).
 *
 * - `idle`: the manager has not been started (signed out).
 * - `connecting`: first connection attempt in progress.
 * - `connected`: stream open.
 * - `reconnecting`: the stream dropped recently; data on screen may lag.
 * - `stale`: the stream has been down longer than the stale threshold; data on screen may be out of date.
 * - `disconnected`: automatic retries are exhausted; the operator must reconnect (or reload).
 */
export type SseStatus = 'idle' | 'connecting' | 'connected' | 'reconnecting' | 'stale' | 'disconnected';

export interface SseState {
  status: SseStatus;
  /** Client clock time (ms) of the last received event. */
  lastEventAt: number | null;
  /** Client clock time (ms) when the current outage began. */
  disconnectedAt: number | null;
  /** Number of consecutive failed connection attempts. */
  attempt: number;
}

export const initialSseState: SseState = {
  status: 'idle',
  lastEventAt: null,
  disconnectedAt: null,
  attempt: 0,
};

export const sseStore = new Store<SseState>(initialSseState);

export function useSseState(): SseState {
  return useSelector(sseStore, (s) => s);
}

export function useSseStatus(): SseStatus {
  return useSelector(sseStore, (s) => s.status);
}
