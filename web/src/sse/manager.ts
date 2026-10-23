import type { QueryClient } from '@tanstack/react-query';
import type { Store } from '@tanstack/react-store';

import type { LiveEvent } from '../api/types';
import { sseStore, type SseState, type SseStatus } from '../stores/sse';
import { keysForEvent } from './invalidation';

/**
 * Live-event stream manager for `GET /api/v1/events` (docs/PLAN.md §8.3, §14.4, HP-API-005).
 *
 * Resume semantics:
 * - While one EventSource object lives, the browser reconnects by itself (server `retry: 3000`) and sends
 *   `Last-Event-ID`; the server replays missed events or sends `reset`. Nothing extra is needed here.
 * - When the browser gives up (readyState CLOSED: HTTP error, wrong content type), this manager creates a
 *   new EventSource after an exponential backoff. A new object cannot send `Last-Event-ID`, so the manager
 *   invalidates every query once the new stream opens. The very first open also invalidates everything,
 *   because data fetched before the stream existed may have missed events.
 * - `reset` invalidates every query.
 *
 * Heartbeats are SSE comments, which EventSource does not expose; staleness is therefore derived from the
 * connection state (`stale` after `staleAfterMs` without an open stream), not from heartbeat gaps.
 */

/** Subset of EventSource used by the manager (allows a fake in tests). */
export interface EventSourceLike {
  readonly readyState: number;
  onopen: ((this: EventSourceLike, ev: Event) => unknown) | null;
  onerror: ((this: EventSourceLike, ev: Event) => unknown) | null;
  addEventListener(type: string, listener: (ev: MessageEvent<string>) => void): void;
  close(): void;
}

export type EventSourceFactory = (url: string) => EventSourceLike;

export const EVENT_SOURCE_CLOSED = 2;

/** Event types from docs/PLAN.md §8.3. `message` catches frames without an `event:` field. */
export const LIVE_EVENT_TYPES = [
  'request.created',
  'request.updated',
  'grant.updated',
  'session.updated',
  'activity.started',
  'activity.ended',
  'notification.updated',
  'audit.appended',
  'system.status',
  'policy.changed',
  'reset',
  'message',
] as const;

export interface BackoffOptions {
  initialMs: number;
  maxMs: number;
  factor: number;
  /** Fraction (0..1) of the delay that is randomized downward. */
  jitter: number;
}

export const DEFAULT_BACKOFF: BackoffOptions = { initialMs: 1_000, maxMs: 30_000, factor: 2, jitter: 0.2 };

/** Delay before reconnect attempt `attempt` (0-based): capped exponential with downward jitter. */
export function backoffDelay(
  attempt: number,
  options: BackoffOptions = DEFAULT_BACKOFF,
  random = Math.random,
): number {
  const base = Math.min(options.maxMs, options.initialMs * options.factor ** Math.max(0, attempt));
  return Math.round(base * (1 - options.jitter * random()));
}

export interface SseManagerOptions {
  queryClient: Pick<QueryClient, 'invalidateQueries'>;
  url?: string;
  createEventSource?: EventSourceFactory;
  store?: Store<SseState>;
  backoff?: Partial<BackoffOptions>;
  /** How long the stream may be down before the UI shows data as stale. */
  staleAfterMs?: number;
  /** Manual reconnect attempts before giving up (`disconnected`). */
  maxAttempts?: number;
  random?: () => number;
  now?: () => number;
  onEvent?: (event: LiveEvent) => void;
}

function parseLiveEvent(type: string, data: string): LiveEvent | null {
  if (type === 'reset') {
    return { type: 'reset', resource: '' };
  }
  try {
    const value = JSON.parse(data) as unknown;
    if (typeof value !== 'object' || value === null) {
      return null;
    }
    const v = value as Record<string, unknown>;
    if (typeof v.resource !== 'string') {
      return null;
    }
    return {
      type: typeof v.type === 'string' ? v.type : type,
      resource: v.resource,
      ...(typeof v.resource_id === 'string' ? { resource_id: v.resource_id } : {}),
      ...(typeof v.version === 'number' ? { version: v.version } : {}),
      ...(typeof v.at === 'string' ? { at: v.at } : {}),
    };
  } catch {
    return null;
  }
}

export class SseManager {
  private readonly queryClient: Pick<QueryClient, 'invalidateQueries'>;
  private readonly url: string;
  private readonly createEventSource: EventSourceFactory;
  private readonly store: Store<SseState>;
  private readonly backoff: BackoffOptions;
  private readonly staleAfterMs: number;
  private readonly maxAttempts: number;
  private readonly random: () => number;
  private readonly now: () => number;
  private readonly onEvent: ((event: LiveEvent) => void) | undefined;

  private es: EventSourceLike | null = null;
  private running = false;
  private attempt = 0;
  private invalidateAllOnOpen = true;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private staleTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: SseManagerOptions) {
    this.queryClient = options.queryClient;
    this.url = options.url ?? '/api/v1/events';
    this.createEventSource =
      options.createEventSource ??
      ((url) => new EventSource(url, { withCredentials: false }) as EventSourceLike);
    this.store = options.store ?? sseStore;
    this.backoff = { ...DEFAULT_BACKOFF, ...options.backoff };
    this.staleAfterMs = options.staleAfterMs ?? 10_000;
    this.maxAttempts = options.maxAttempts ?? 20;
    this.random = options.random ?? Math.random;
    this.now = options.now ?? (() => Date.now());
    this.onEvent = options.onEvent;
  }

  get isRunning(): boolean {
    return this.running;
  }

  start(): void {
    if (this.running) {
      return;
    }
    this.running = true;
    this.attempt = 0;
    this.invalidateAllOnOpen = true;
    if (typeof window !== 'undefined') {
      window.addEventListener('online', this.handleOnline);
    }
    this.update({ status: 'connecting', attempt: 0, disconnectedAt: null });
    this.connect();
  }

  stop(): void {
    this.running = false;
    if (typeof window !== 'undefined') {
      window.removeEventListener('online', this.handleOnline);
    }
    this.clearTimers();
    this.closeSource();
    this.update({ status: 'idle', attempt: 0, disconnectedAt: null });
  }

  /** Drops any current stream and connects immediately (operator "Reconnect" action, `online` event). */
  reconnectNow(): void {
    if (!this.running) {
      this.start();
      return;
    }
    this.clearRetryTimer();
    this.closeSource();
    this.attempt = 0;
    this.invalidateAllOnOpen = true;
    this.markDown();
    this.connect();
  }

  private readonly handleOnline = (): void => {
    if (this.store.state.status !== 'connected') {
      this.reconnectNow();
    }
  };

  private connect(): void {
    let es: EventSourceLike;
    try {
      es = this.createEventSource(this.url);
    } catch {
      // EventSource unavailable or the URL was rejected: degrade visibly instead of breaking the page.
      this.markDown();
      this.invalidateAllOnOpen = true;
      this.scheduleRetry();
      return;
    }
    this.es = es;
    es.onopen = () => {
      if (this.es !== es) {
        return;
      }
      this.attempt = 0;
      this.clearStaleTimer();
      this.update({ status: 'connected', attempt: 0, disconnectedAt: null });
      if (this.invalidateAllOnOpen) {
        this.invalidateAllOnOpen = false;
        void this.queryClient.invalidateQueries();
      }
    };
    es.onerror = () => {
      if (this.es !== es) {
        return;
      }
      this.markDown();
      if (es.readyState === EVENT_SOURCE_CLOSED) {
        // The browser will not retry this object; schedule our own reconnect with a fresh EventSource.
        this.closeSource();
        this.invalidateAllOnOpen = true;
        this.scheduleRetry();
      }
    };
    for (const type of LIVE_EVENT_TYPES) {
      es.addEventListener(type, (ev) => {
        if (this.es === es) {
          this.handleEvent(type, ev);
        }
      });
    }
  }

  private handleEvent(type: string, ev: MessageEvent<string>): void {
    this.update({ lastEventAt: this.now() });
    const event = parseLiveEvent(type, typeof ev.data === 'string' ? ev.data : '');
    const keys = event ? keysForEvent(event) : null;
    if (keys === null) {
      // reset, unknown resource or malformed frame: refetch everything rather than risk stale state.
      void this.queryClient.invalidateQueries();
    } else {
      for (const queryKey of keys) {
        void this.queryClient.invalidateQueries({ queryKey });
      }
    }
    if (event) {
      this.onEvent?.(event);
    }
  }

  private markDown(): void {
    const now = this.now();
    this.store.setState((s) => {
      const status: SseStatus =
        s.status === 'stale' || s.status === 'disconnected' ? s.status : 'reconnecting';
      return { ...s, status, disconnectedAt: s.disconnectedAt ?? now };
    });
    this.staleTimer ??= setTimeout(() => {
      this.staleTimer = null;
      if (this.running && this.store.state.status === 'reconnecting') {
        this.update({ status: 'stale' });
      }
    }, this.staleAfterMs);
  }

  private scheduleRetry(): void {
    if (!this.running) {
      return;
    }
    if (this.attempt >= this.maxAttempts) {
      this.clearStaleTimer();
      this.update({ status: 'disconnected', attempt: this.attempt });
      return;
    }
    const delay = backoffDelay(this.attempt, this.backoff, this.random);
    this.attempt += 1;
    this.update({ attempt: this.attempt });
    this.clearRetryTimer();
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      if (this.running) {
        this.connect();
      }
    }, delay);
  }

  private update(patch: Partial<SseState>): void {
    this.store.setState((s) => ({ ...s, ...patch }));
  }

  private closeSource(): void {
    if (this.es) {
      const es = this.es;
      this.es = null;
      es.onopen = null;
      es.onerror = null;
      es.close();
    }
  }

  private clearRetryTimer(): void {
    if (this.retryTimer !== null) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
  }

  private clearStaleTimer(): void {
    if (this.staleTimer !== null) {
      clearTimeout(this.staleTimer);
      this.staleTimer = null;
    }
  }

  private clearTimers(): void {
    this.clearRetryTimer();
    this.clearStaleTimer();
  }
}
