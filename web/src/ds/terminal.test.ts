import { Terminal } from '@xterm/xterm';
import { describe, expect, it, vi } from 'vitest';

import {
  hardenTerminal,
  MAX_WRITE_BYTES,
  SAFE_TERMINAL_OPTIONS,
  SWALLOWED_OSC,
  writeBounded,
} from './terminal';

describe('replay terminal hardening', () => {
  it('uses read-only, no-proposed-API options with an inert link handler', () => {
    expect(SAFE_TERMINAL_OPTIONS.disableStdin).toBe(true);
    expect(SAFE_TERMINAL_OPTIONS.allowProposedApi).toBe(false);
    expect(SAFE_TERMINAL_OPTIONS.linkHandler?.allowNonHttpProtocols).toBe(false);
    const open = vi.spyOn(window, 'open');
    SAFE_TERMINAL_OPTIONS.linkHandler?.activate(new MouseEvent('click'), 'https://evil.example', {
      start: { x: 1, y: 1 },
      end: { x: 2, y: 1 },
    });
    expect(open).not.toHaveBeenCalled();
  });

  it('registers swallowing handlers for title, hyperlink and clipboard OSCs', () => {
    const registered: number[] = [];
    const fake = {
      parser: {
        registerOscHandler: (ident: number, cb: (data: string) => boolean | Promise<boolean>) => {
          registered.push(ident);
          expect(cb('payload')).toBe(true);
          return { dispose: () => undefined };
        },
      },
    } as unknown as Pick<Terminal, 'parser'>;
    expect(hardenTerminal(fake)).toHaveLength(SWALLOWED_OSC.length);
    expect(registered).toEqual([0, 1, 2, 8, 52]);
  });

  it('does not emit title changes for hostile OSC sequences', async () => {
    const term = new Terminal({ ...SAFE_TERMINAL_OPTIONS });
    hardenTerminal(term);
    const titles: string[] = [];
    term.onTitleChange((t) => titles.push(t));
    const evil =
      '\x1b]0;pwned\x07\x1b]2;pwned\x07\x1b]8;;javascript:alert(1)\x07click\x1b]8;;\x07\x1b]52;c;ZXZpbA==\x07done';
    await new Promise<void>((resolve) => {
      term.write(evil, resolve);
    });
    expect(titles).toEqual([]);
    term.dispose();
  });
});

describe('malicious recording corpus (HP-UI-013, WP21)', () => {
  const enc = (s: string) => new TextEncoder().encode(s);

  async function feed(chunks: (string | Uint8Array)[]) {
    const term = new Terminal({ ...SAFE_TERMINAL_OPTIONS, cols: 80, rows: 24 });
    const guards = hardenTerminal(term);
    const titles: string[] = [];
    const bells: number[] = [];
    const data: string[] = [];
    term.onTitleChange((t) => titles.push(t));
    term.onBell(() => bells.push(1));
    term.onData((d) => data.push(d));
    term.onBinary((d) => data.push(d));
    const open = vi.spyOn(window, 'open');
    const clipboard = vi.fn();
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: clipboard }, configurable: true });
    for (const chunk of chunks) {
      writeBounded(term, chunk);
    }
    await new Promise<void>((resolve) => {
      term.write('', resolve);
    });
    const text = Array.from(
      { length: term.buffer.active.length },
      (_, i) => term.buffer.active.getLine(i)?.translateToString(true) ?? '',
    ).join('\n');
    const result = { term, titles, bells, data, open, clipboard, text };
    for (const g of guards) {
      g.dispose();
    }
    return result;
  }

  it('swallows OSC 8 hyperlinks, OSC 52 clipboard writes and OSC 0/1/2 titles', async () => {
    const r = await feed([
      enc('\x1b]8;;https://evil.example/\x1b\\click me\x1b]8;;\x1b\\\r\n'),
      enc('\x1b]8;id=1;javascript:alert(1)\x07js\x1b]8;;\x07\r\n'),
      enc('\x1b]52;c;cm0gLXJmIC8K\x07\x1b]52;p;?\x07'),
      enc('\x1b]0;pwned\x07\x1b]1;icon\x07\x1b]2;title\x1b\\'),
      'done',
    ]);
    expect(r.titles).toEqual([]);
    expect(r.clipboard).not.toHaveBeenCalled();
    expect(r.open).not.toHaveBeenCalled();
    // Status reports and other replies never leave the read-only terminal.
    expect(r.data).toEqual([]);
    expect(r.text).toContain('click me');
    expect(r.text).not.toContain('evil.example');
    expect(r.text).toContain('done');
    r.term.dispose();
  });

  it('does not answer device queries (DA/DSR) from recorded output', async () => {
    const r = await feed([enc('\x1b[c\x1b[6n\x1b[>c\x1b]10;?\x07')]);
    expect(r.data).toEqual([]);
    r.term.dispose();
  });

  it('handles a huge single line and invalid UTF-8 without throwing', async () => {
    const huge = new Uint8Array(200_000).fill(0x41);
    const invalid = new Uint8Array([0xff, 0xfe, 0xc3, 0x28, 0xe2, 0x82, 0x0a, 0xf0, 0x90, 0x28, 0xbc]);
    const write = vi.fn();
    writeBounded({ write }, huge);
    expect(write.mock.calls.every(([chunk]) => (chunk as Uint8Array).length <= MAX_WRITE_BYTES)).toBe(true);
    expect(write).toHaveBeenCalledTimes(Math.ceil(huge.length / MAX_WRITE_BYTES));
    const r = await feed([huge, invalid, enc('\r\nend')]);
    expect(r.text).toContain('end');
    r.term.dispose();
  });
});
