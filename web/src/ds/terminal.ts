import type { IDisposable, ITerminalInitOnlyOptions, ITerminalOptions, Terminal } from '@xterm/xterm';

import { fontFamilyCode } from './theme/tokens';

/**
 * Replay-safety configuration for xterm.js (docs/PLAN.md §14.5, HP-UI-013).
 *
 * Recorded output is attacker-influenced (agents and destinations control it). The terminal therefore:
 * - is read-only (`disableStdin`), so escape-sequence replies never go anywhere;
 * - has a link handler that does nothing (the default one would `window.open` after a confirm);
 * - swallows OSC 8 (hyperlinks), OSC 52 (clipboard) and OSC 0/1/2 (title/icon) before xterm sees them;
 * - never subscribes to `onTitleChange` or `onBell`;
 * - does not enable proposed APIs or load the WebLinks addon.
 */
export const SAFE_TERMINAL_OPTIONS: ITerminalOptions & ITerminalInitOnlyOptions = {
  disableStdin: true,
  allowProposedApi: false,
  allowTransparency: false,
  convertEol: false,
  cursorBlink: false,
  cursorStyle: 'underline',
  scrollback: 5_000,
  fontFamily: fontFamilyCode,
  fontSize: 13,
  linkHandler: {
    activate: () => undefined,
    allowNonHttpProtocols: false,
  },
};

/**
 * Options for one replay terminal. Channels without a PTY (exec, or a shell opened without a terminal)
 * emit bare LF line endings because no terminal line discipline translated them; xterm must convert LF to
 * CRLF there or every line starts where the previous one ended. PTY output already carries CRLF and is
 * replayed raw. Everything else stays the hardened SAFE_TERMINAL_OPTIONS.
 */
export function replayTerminalOptions({
  pty,
}: {
  pty: boolean;
}): ITerminalOptions & ITerminalInitOnlyOptions {
  return { ...SAFE_TERMINAL_OPTIONS, convertEol: !pty };
}

/** OSC identifiers swallowed during replay. */
export const SWALLOWED_OSC = [0, 1, 2, 8, 52] as const;

export function hardenTerminal(term: Pick<Terminal, 'parser'>): IDisposable[] {
  return SWALLOWED_OSC.map((ident) => term.parser.registerOscHandler(ident, () => true));
}

/** Largest single write into the emulator; recorded output is fed in bounded chunks (HP-UI-013). */
export const MAX_WRITE_BYTES = 16 * 1024;

/** Writes `data` in chunks of at most MAX_WRITE_BYTES (strings are chunked by UTF-16 units). */
export function writeBounded(term: Pick<Terminal, 'write'>, data: Uint8Array | string): void {
  for (let i = 0; i < data.length; i += MAX_WRITE_BYTES) {
    term.write(
      typeof data === 'string' ? data.slice(i, i + MAX_WRITE_BYTES) : data.subarray(i, i + MAX_WRITE_BYTES),
    );
  }
}
