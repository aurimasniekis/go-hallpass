import { Terminal } from '@xterm/xterm';
import { describe, expect, it, vi } from 'vitest';

import { hardenTerminal, SAFE_TERMINAL_OPTIONS, SWALLOWED_OSC } from './terminal';

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
