import { Store } from '@tanstack/react-store';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { initialSseState, type SseState } from '../stores/sse';
import { backoffDelay, EVENT_SOURCE_CLOSED, SseManager, type EventSourceLike } from './manager';

class FakeEventSource implements EventSourceLike {
  static instances: FakeEventSource[] = [];
  readyState = 0;
  onopen: EventSourceLike['onopen'] = null;
  onerror: EventSourceLike['onerror'] = null;
  closed = false;
  private listeners = new Map<string, ((ev: MessageEvent<string>) => void)[]>();

  constructor(readonly url: string) {
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: (ev: MessageEvent<string>) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener]);
  }

  close(): void {
    this.closed = true;
    this.readyState = EVENT_SOURCE_CLOSED;
  }

  open(): void {
    this.readyState = 1;
    this.onopen?.call(this, new Event('open'));
  }

  /** Network drop while the browser keeps retrying (readyState CONNECTING). */
  drop(): void {
    this.readyState = 0;
    this.onerror?.call(this, new Event('error'));
  }

  /** Browser gave up (e.g. HTTP 401/502). */
  fail(): void {
    this.readyState = EVENT_SOURCE_CLOSED;
    this.onerror?.call(this, new Event('error'));
  }

  emit(type: string, data: unknown): void {
    const ev = new MessageEvent<string>(type, {
      data: typeof data === 'string' ? data : JSON.stringify(data),
    });
    for (const l of this.listeners.get(type) ?? []) {
      l(ev);
    }
  }
}

function latest(): FakeEventSource {
  const es = FakeEventSource.instances.at(-1);
  if (!es) {
    throw new Error('no EventSource created');
  }
  return es;
}

function setup(overrides: { maxAttempts?: number } = {}) {
  const store = new Store<SseState>(initialSseState);
  const invalidateQueries = vi.fn(() => Promise.resolve());
  const manager = new SseManager({
    queryClient: { invalidateQueries },
    createEventSource: (url) => new FakeEventSource(url),
    store,
    staleAfterMs: 5_000,
    random: () => 0,
    ...overrides,
  });
  return { store, invalidateQueries, manager };
}

describe('backoffDelay', () => {
  it('grows exponentially, caps, and applies downward jitter', () => {
    const opts = { initialMs: 1000, maxMs: 30_000, factor: 2, jitter: 0.2 };
    expect([0, 1, 2, 3, 4, 5, 6].map((a) => backoffDelay(a, opts, () => 0))).toEqual([
      1000, 2000, 4000, 8000, 16000, 30000, 30000,
    ]);
    expect(backoffDelay(0, opts, () => 1)).toBe(800);
  });
});

describe('SseManager', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    FakeEventSource.instances = [];
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('connects, reports status and invalidates everything on the first open', () => {
    const { store, invalidateQueries, manager } = setup();
    manager.start();
    expect(store.state.status).toBe('connecting');
    expect(latest().url).toBe('/api/v1/events');
    latest().open();
    expect(store.state.status).toBe('connected');
    expect(invalidateQueries).toHaveBeenCalledWith();
    manager.stop();
    expect(store.state.status).toBe('idle');
    expect(latest().closed).toBe(true);
  });

  it('invalidates the query keys mapped from the event resource', () => {
    const { invalidateQueries, manager, store } = setup();
    manager.start();
    latest().open();
    invalidateQueries.mockClear();
    latest().emit('request.updated', {
      type: 'request.updated',
      resource: 'request',
      resource_id: 'r1',
      version: 3,
    });
    expect(invalidateQueries.mock.calls).toEqual([
      [{ queryKey: ['requests'] }],
      [{ queryKey: ['request', 'r1'] }],
      [{ queryKey: ['stats'] }],
    ]);
    expect(store.state.lastEventAt).not.toBeNull();
  });

  it('invalidates everything on reset and on malformed frames', () => {
    const { invalidateQueries, manager } = setup();
    manager.start();
    latest().open();
    invalidateQueries.mockClear();
    latest().emit('reset', '{}');
    latest().emit('message', 'not json');
    expect(invalidateQueries.mock.calls).toEqual([[], []]);
  });

  it('shows reconnecting then stale while the browser retries, without a full refetch on resume', () => {
    const { store, invalidateQueries, manager } = setup();
    manager.start();
    const es = latest();
    es.open();
    invalidateQueries.mockClear();

    es.drop();
    expect(store.state.status).toBe('reconnecting');
    expect(store.state.disconnectedAt).not.toBeNull();
    vi.advanceTimersByTime(5_000);
    expect(store.state.status).toBe('stale');

    es.open(); // browser resumed with Last-Event-ID
    expect(store.state.status).toBe('connected');
    expect(store.state.disconnectedAt).toBeNull();
    expect(invalidateQueries).not.toHaveBeenCalled();
    expect(FakeEventSource.instances).toHaveLength(1);
  });

  it('recreates the EventSource with backoff when the browser gives up, then refetches everything', () => {
    const { store, invalidateQueries, manager } = setup();
    manager.start();
    latest().open();
    invalidateQueries.mockClear();

    latest().fail();
    expect(store.state.status).toBe('reconnecting');
    expect(FakeEventSource.instances).toHaveLength(1);
    vi.advanceTimersByTime(999);
    expect(FakeEventSource.instances).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(FakeEventSource.instances).toHaveLength(2);

    latest().fail();
    vi.advanceTimersByTime(1_999);
    expect(FakeEventSource.instances).toHaveLength(2);
    vi.advanceTimersByTime(1);
    expect(FakeEventSource.instances).toHaveLength(3);

    latest().open();
    expect(store.state.status).toBe('connected');
    expect(store.state.attempt).toBe(0);
    expect(invalidateQueries).toHaveBeenCalledWith();
  });

  it('gives up after maxAttempts and can be reconnected manually', () => {
    const { store, manager } = setup({ maxAttempts: 2 });
    manager.start();
    latest().fail();
    vi.advanceTimersByTime(1_000);
    latest().fail();
    vi.advanceTimersByTime(2_000);
    latest().fail();
    expect(store.state.status).toBe('disconnected');
    vi.advanceTimersByTime(60_000);
    expect(FakeEventSource.instances).toHaveLength(3);

    manager.reconnectNow();
    expect(FakeEventSource.instances).toHaveLength(4);
    latest().open();
    expect(store.state.status).toBe('connected');
  });

  it('ignores events from a replaced EventSource', () => {
    const { invalidateQueries, manager } = setup();
    manager.start();
    const first = latest();
    first.open();
    manager.reconnectNow();
    invalidateQueries.mockClear();
    first.emit('request.created', { resource: 'request' });
    expect(invalidateQueries).not.toHaveBeenCalled();
    expect(first.closed).toBe(true);
  });

  it('degrades to reconnecting/disconnected when EventSource cannot be created', () => {
    const store = new Store<SseState>(initialSseState);
    const manager = new SseManager({
      queryClient: { invalidateQueries: vi.fn(() => Promise.resolve()) },
      createEventSource: () => {
        throw new ReferenceError('EventSource is not defined');
      },
      store,
      maxAttempts: 1,
      random: () => 0,
    });
    expect(() => {
      manager.start();
    }).not.toThrow();
    expect(store.state.status).toBe('reconnecting');
    vi.advanceTimersByTime(1_000);
    expect(store.state.status).toBe('disconnected');
  });
});
