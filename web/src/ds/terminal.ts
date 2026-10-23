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

/** OSC identifiers swallowed during replay. */
export const SWALLOWED_OSC = [0, 1, 2, 8, 52] as const;

export function hardenTerminal(term: Pick<Terminal, 'parser'>): IDisposable[] {
  return SWALLOWED_OSC.map((ident) => term.parser.registerOscHandler(ident, () => true));
}
