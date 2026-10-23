/**
 * Replay player state machine (WP21). Pure: time comes from an injected clock and effects go to a sink,
 * so it is unit-tested without timers or a DOM.
 *
 * States: `idle` (no track) → `ready` → `playing` ⇄ `paused` → `ended`. Seeking backwards resets the sink
 * and re-applies frames from the start up to the target; seeking forward applies the frames in between.
 */

export interface Clock {
  now: () => number;
  setTimeout: (fn: () => void, ms: number) => unknown;
  clearTimeout: (handle: unknown) => void;
}

export const realClock: Clock = {
  now: () => performance.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (h) => {
    clearTimeout(h as ReturnType<typeof setTimeout>);
  },
};

export interface TimedFrame {
  t: number;
}

export interface PlayerSink<F extends TimedFrame> {
  /** Clear all output (before replaying from the start). */
  reset: () => void;
  apply: (frame: F) => void;
}

export type PlayerStatus = 'idle' | 'ready' | 'playing' | 'paused' | 'ended';

export interface PlayerSnapshot {
  status: PlayerStatus;
  positionMs: number;
  durationMs: number;
  speed: number;
}

export const SPEEDS = [0.5, 1, 2, 4, 8] as const;
export const MIN_SPEED = 0.5;
export const MAX_SPEED = 8;

export class ReplayPlayer<F extends TimedFrame> {
  private frames: readonly F[] = [];
  private duration = 0;
  private next = 0;
  private status: PlayerStatus = 'idle';
  private speed = 1;
  private basePos = 0;
  private baseWall = 0;
  private timer: unknown = null;

  constructor(
    private readonly sink: PlayerSink<F>,
    private readonly clock: Clock = realClock,
    private readonly onChange?: (s: PlayerSnapshot) => void,
  ) {}

  /** Loads a track (frames sorted by `t`) and rewinds to the start. */
  load(frames: readonly F[], durationMs: number): void {
    this.stopTimer();
    this.frames = frames;
    this.duration = Math.max(durationMs, frames.at(-1)?.t ?? 0);
    this.next = 0;
    this.basePos = 0;
    this.sink.reset();
    this.status = 'ready';
    this.emit();
  }

  snapshot(): PlayerSnapshot {
    return { status: this.status, positionMs: this.position(), durationMs: this.duration, speed: this.speed };
  }

  position(): number {
    if (this.status === 'playing') {
      return Math.min(this.duration, this.basePos + (this.clock.now() - this.baseWall) * this.speed);
    }
    return this.basePos;
  }

  play(): void {
    if (this.status === 'idle' || this.status === 'playing') {
      return;
    }
    if (this.status === 'ended') {
      this.seek(0);
    }
    this.status = 'playing';
    this.baseWall = this.clock.now();
    this.emit();
    this.step();
  }

  pause(): void {
    if (this.status !== 'playing') {
      return;
    }
    this.basePos = this.position();
    this.stopTimer();
    this.status = 'paused';
    this.emit();
  }

  toggle(): void {
    if (this.status === 'playing') {
      this.pause();
    } else {
      this.play();
    }
  }

  setSpeed(speed: number): void {
    const s = Math.min(MAX_SPEED, Math.max(MIN_SPEED, Number.isFinite(speed) ? speed : 1));
    if (this.status === 'playing') {
      this.basePos = this.position();
      this.baseWall = this.clock.now();
      this.speed = s;
      this.step();
    } else {
      this.speed = s;
    }
    this.emit();
  }

  seek(targetMs: number): void {
    if (this.status === 'idle') {
      return;
    }
    const target = Math.min(this.duration, Math.max(0, Number.isFinite(targetMs) ? targetMs : 0));
    const applied = this.next > 0 ? (this.frames[this.next - 1]?.t ?? 0) : -1;
    // A frame later than the target was already applied: rebuild the output from the start.
    if (target < applied) {
      this.sink.reset();
      this.next = 0;
    }
    this.applyUntil(target);
    this.basePos = target;
    this.baseWall = this.clock.now();
    if (this.status === 'playing') {
      this.step();
    } else if (this.status === 'ended' && target < this.duration) {
      this.status = 'paused';
    }
    this.emit();
  }

  dispose(): void {
    this.stopTimer();
    this.status = 'idle';
  }

  private applyUntil(pos: number): void {
    while (this.next < this.frames.length) {
      const f = this.frames[this.next];
      if (f === undefined || f.t > pos) {
        break;
      }
      this.sink.apply(f);
      this.next += 1;
    }
  }

  private step = (): void => {
    this.stopTimer();
    if (this.status !== 'playing') {
      return;
    }
    const pos = this.position();
    this.applyUntil(pos);
    if (this.next >= this.frames.length && pos >= this.duration) {
      this.basePos = this.duration;
      this.status = 'ended';
      this.emit();
      return;
    }
    const nextT =
      this.next < this.frames.length ? (this.frames[this.next]?.t ?? this.duration) : this.duration;
    const delay = Math.max(0, (nextT - pos) / this.speed);
    this.timer = this.clock.setTimeout(this.step, delay);
  };

  private stopTimer(): void {
    if (this.timer !== null) {
      this.clock.clearTimeout(this.timer);
      this.timer = null;
    }
  }

  private emit(): void {
    this.onChange?.(this.snapshot());
  }
}

/** `mm:ss` (or `h:mm:ss`) for the replay time display. */
export function formatClock(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  return h > 0 ? `${String(h)}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}
