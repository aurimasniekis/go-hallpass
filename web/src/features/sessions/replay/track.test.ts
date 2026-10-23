import { describe, expect, it } from 'vitest';

import type { SegmentLoad } from './pager';
import { buildTrack, chunkBytes } from './track';
import { enc, lenBytes, rec, uvarint } from './testutil';

function load(records: ReturnType<typeof rec>[], extra: Partial<SegmentLoad> = {}): SegmentLoad {
  return {
    segmentId: 's',
    records,
    complete: true,
    incomplete: false,
    truncated: false,
    pages: 1,
    duplicates: 0,
    ...extra,
  };
}

const pty = [...uvarint(100), ...uvarint(30), 0, 0, ...lenBytes(enc('xterm')), ...lenBytes([])];

describe('buildTrack', () => {
  it('builds PTY frames with initial size, resizes and skipped input', () => {
    const track = buildTrack('pty', [
      {
        segment: { id: 's1', ordinal: 0 },
        load: load([
          rec(1, 'pty.requested@1', pty, 0),
          rec(2, 'terminal.output@1', enc('$ '), 10),
          rec(3, 'terminal.input@1', enc('secret\r'), 500),
          rec(4, 'terminal.resized@1', [...uvarint(120), ...uvarint(40), 0, 0], 600),
          rec(5, 'terminal.output@1', enc('ok'), 700),
          rec(6, 'mystery@9', enc('<b>x</b>'), 800),
          rec(7, 'terminal.resized@1', [1, 2], 900),
        ]),
      },
    ]);
    expect(track.initialSize).toEqual({ cols: 100, rows: 30 });
    expect(track.term).toBe('xterm');
    expect(track.frames.map((f) => f.kind)).toEqual(['output', 'resize', 'output']);
    expect(track.frames[1]).toMatchObject({ cols: 120, rows: 40, t: 600 });
    expect(track.inputRecords).toBe(1);
    expect(track.unknownRecords).toBe(1);
    expect(track.invalidRecords).toBe(1);
    expect(track.durationMs).toBe(900);
  });

  it('labels the exec command as captured (never verified) and splits stdout/stderr', () => {
    const track = buildTrack('exec', [
      {
        segment: { id: 's1', ordinal: 0 },
        load: load([
          rec(1, 'exec.requested@1', enc('uname -a'), 0, 'meta'),
          rec(2, 'stdout@1', enc('Linux\n'), 5, 'stdout'),
          rec(3, 'stderr@1', enc('warn\n'), 6, 'stderr'),
          rec(4, 'exit@1', [0, 0], 7, 'meta'),
        ]),
      },
    ]);
    expect(track.command).toEqual({ text: 'uname -a', provenance: 'captured' });
    expect(JSON.stringify(track)).not.toMatch(/verified/i);
    expect(track.frames.map((f) => f.kind)).toEqual(['stdout', 'stderr']);
    expect(track.events[0]).toMatchObject({ kind: 'exit', exit: { status: 0 } });
  });

  it('orders segments by ordinal, keeps time monotonic and propagates incomplete', () => {
    const track = buildTrack('pty', [
      {
        segment: { id: 'b', ordinal: 1 },
        load: load([rec(10, 'terminal.output@1', enc('b'), 2000)], { incomplete: true }),
      },
      {
        segment: { id: 'a', ordinal: 0 },
        load: load([rec(1, 'terminal.output@1', enc('a'), 0), rec(2, 'terminal.output@1', enc('a'), 300)]),
      },
    ]);
    const ts = track.frames.map((f) => f.t);
    expect(ts).toEqual([...ts].sort((x, y) => x - y));
    expect(new TextDecoder().decode(track.frames[2]?.bytes)).toBe('b');
    expect(track.incomplete).toBe(true);
  });

  it('caps idle gaps when requested', () => {
    const track = buildTrack(
      'pty',
      [
        {
          segment: { id: 'a', ordinal: 0 },
          load: load([
            rec(1, 'terminal.output@1', enc('a'), 0),
            rec(2, 'terminal.output@1', enc('b'), 60_000),
          ]),
        },
      ],
      { idleCapMs: 2000 },
    );
    expect(track.durationMs).toBe(2000);
  });
});

describe('chunkBytes', () => {
  it('splits into bounded chunks', () => {
    const chunks = chunkBytes(new Uint8Array(40_000), 16_384);
    expect(chunks.map((c) => c.length)).toEqual([16_384, 16_384, 7_232]);
    expect(chunkBytes(new Uint8Array(3))).toHaveLength(1);
  });
});
