import '@xterm/xterm/css/xterm.css';

import { Terminal } from '@xterm/xterm';
import { useEffect, useRef } from 'react';

import { hardenTerminal, SAFE_TERMINAL_OPTIONS } from './terminal';

export interface TerminalReplayProps {
  /** Output chunks to render, in order. Fed in bounded pieces by the caller (WP21). */
  chunks: readonly (string | Uint8Array)[];
  ariaLabel: string;
  rows?: number;
  cols?: number;
}

/**
 * STUB (WP19): mounts a hardened, read-only xterm.js terminal and writes the given chunks.
 * Real replay (records API paging, timeline positioning, per-stream selection, exec panes) is WP21.
 */
export function TerminalReplay({ chunks, ariaLabel, rows = 16, cols = 100 }: TerminalReplayProps) {
  const el = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const node = el.current;
    if (!node) {
      return;
    }
    const term = new Terminal({ ...SAFE_TERMINAL_OPTIONS, rows, cols });
    const guards = hardenTerminal(term);
    term.open(node);
    for (const chunk of chunks) {
      term.write(chunk);
    }
    return () => {
      for (const g of guards) {
        g.dispose();
      }
      term.dispose();
    };
  }, [chunks, rows, cols]);

  return <div ref={el} className="hp-terminal" role="region" aria-label={ariaLabel} />;
}
