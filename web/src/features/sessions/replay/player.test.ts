import { describe, expect, it } from 'vitest';

import { formatClock, ReplayPlayer, type Clock, type PlayerSnapshot } from './player';

class FakeClock implements Clock {
  t = 0;
  private timers: { at: number; fn: () => void; id: number }[] = [];
  private id = 0;
  now = () => this.t;
  setTimeout = (fn: () => void, ms: number) => {
    this.id += 1;
    this.timers.push({ at: this.t + ms, fn, id: this.id });
    return this.id;
  };
  clearTimeout = (h: unknown) => {
    this.timers = this.timers.filter((x) => x.id !== h);
  };
  advance(ms: number) {
    const end = this.t + ms;
    for (;;) {
      this.timers.sort((a, b) => a.at - b.at);
      const next = this.timers[0];
      if (!next || next.at > end) {
        break;
      }
      this.timers.shift();
      this.t = next.at;
      next.fn();
    }
    this.t = end;
  }
}

function setup() {
  const clock = new FakeClock();
  const log: string[] = [];
  const snaps: PlayerSnapshot[] = [];
  const player = new ReplayPlayer<{ t: number; v: string }>(
    { reset: () => log.push('reset'), apply: (f) => log.push(f.v) },
    clock,
    (s) => snaps.push(s),
  );
  player.load(
    [
      { t: 0, v: 'a' },
      { t: 1000, v: 'b' },
      { t: 3000, v: 'c' },
    ],
    3000,
  );
  return { clock, log, snaps, player };
}

describe('ReplayPlayer', () => {
  it('plays frames in time order and ends', () => {
    const { clock, log, player } = setup();
    expect(player.snapshot().status).toBe('ready');
    player.play();
    expect(log).toEqual(['reset', 'a']);
    clock.advance(999);
    expect(log).toEqual(['reset', 'a']);
    clock.advance(1);
    expect(log).toEqual(['reset', 'a', 'b']);
    clock.advance(5000);
    expect(log).toEqual(['reset', 'a', 'b', 'c']);
    expect(player.snapshot()).toMatchObject({ status: 'ended', positionMs: 3000 });
  });

  it('pauses and resumes without losing position', () => {
    const { clock, log, player } = setup();
    player.play();
    clock.advance(500);
    player.pause();
    expect(player.snapshot()).toMatchObject({ status: 'paused', positionMs: 500 });
    clock.advance(10_000);
    expect(log).toEqual(['reset', 'a']);
    player.play();
    clock.advance(500);
    expect(log).toEqual(['reset', 'a', 'b']);
  });

  it('applies speed changes from the current position', () => {
    const { clock, log, player } = setup();
    player.setSpeed(4);
    player.play();
    clock.advance(250);
    expect(log).toEqual(['reset', 'a', 'b']);
    player.setSpeed(100); // clamped to 8x
    expect(player.snapshot().speed).toBe(8);
    clock.advance(250);
    expect(log.at(-1)).toBe('c');
  });

  it('seeks forward by applying the frames in between, and backward by resetting and re-feeding', () => {
    const { log, player } = setup();
    player.seek(2000);
    expect(log).toEqual(['reset', 'a', 'b']);
    player.seek(500);
    expect(log).toEqual(['reset', 'a', 'b', 'reset', 'a']);
    player.seek(-50);
    expect(player.snapshot().positionMs).toBe(0);
    player.seek(99_999);
    expect(player.snapshot().positionMs).toBe(3000);
    expect(log.at(-1)).toBe('c');
  });

  it('restarts from the beginning when played after the end', () => {
    const { clock, log, player } = setup();
    player.play();
    clock.advance(4000);
    expect(player.snapshot().status).toBe('ended');
    player.play();
    expect(log.slice(-2)).toEqual(['reset', 'a']);
    expect(player.snapshot().status).toBe('playing');
  });

  it('does nothing before a track is loaded and stops on dispose', () => {
    const clock = new FakeClock();
    const log: string[] = [];
    const p = new ReplayPlayer<{ t: number }>(
      { reset: () => log.push('reset'), apply: () => log.push('x') },
      clock,
    );
    p.play();
    p.seek(10);
    expect(p.snapshot().status).toBe('idle');
    p.load([{ t: 10 }], 10);
    p.play();
    p.dispose();
    clock.advance(100);
    expect(log).toEqual(['reset']);
  });

  it('formats the clock', () => {
    expect(formatClock(0)).toBe('00:00');
    expect(formatClock(65_500)).toBe('01:05');
    expect(formatClock(3_725_000)).toBe('1:02:05');
  });
});
