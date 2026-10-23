import '@xterm/xterm/css/xterm.css';

import { Terminal } from '@xterm/xterm';
import { useEffect, useImperativeHandle, useRef, type Ref } from 'react';

import { hardenTerminal, replayTerminalOptions, writeBounded } from './terminal';

/** Imperative control used by the replay player (WP21). */
export interface TerminalHandle {
  /** Writes recorded bytes in bounded chunks (HP-UI-013). */
  write: (data: Uint8Array | string) => void;
  /** Clears the screen, scrollback and modes (`term.reset()`), then applies the size. */
  reset: (size?: { cols: number; rows: number }) => void;
  resize: (cols: number, rows: number) => void;
}

export interface TerminalReplayProps {
  /** Static output chunks to render, in order (gallery/fixtures). Replay uses `handleRef` instead. */
  chunks?: readonly (string | Uint8Array)[];
  ariaLabel: string;
  rows?: number;
  cols?: number;
  handleRef?: Ref<TerminalHandle>;
  /**
   * The recorded channel had a PTY. Non-PTY output uses bare LF, which is translated to CRLF
   * (`convertEol`); PTY output is replayed raw. Defaults to true (raw).
   */
  pty?: boolean;
}

/**
 * Hardened, read-only xterm.js terminal (docs/PLAN.md §14.5, HP-UI-013): stdin disabled, inert link
 * handler, OSC 0/1/2/8/52 swallowed, no title/bell subscriptions, no proposed APIs or addons. Recorded
 * bytes are only ever *written* into the emulator; nothing is rendered as HTML.
 */
export function TerminalReplay({
  chunks,
  ariaLabel,
  rows = 24,
  cols = 80,
  handleRef,
  pty = true,
}: TerminalReplayProps) {
  const el = useRef<HTMLDivElement>(null);
  const term = useRef<Terminal | null>(null);

  useEffect(() => {
    const node = el.current;
    if (!node) {
      return;
    }
    const t = new Terminal({ ...replayTerminalOptions({ pty }), rows, cols });
    const guards = hardenTerminal(t);
    t.open(node);
    term.current = t;
    for (const chunk of chunks ?? []) {
      writeBounded(t, chunk);
    }
    return () => {
      term.current = null;
      for (const g of guards) {
        g.dispose();
      }
      t.dispose();
    };
  }, [chunks, rows, cols, pty]);

  useImperativeHandle(
    handleRef,
    () => ({
      write: (data) => {
        if (term.current) {
          writeBounded(term.current, data);
        }
      },
      reset: (size) => {
        const t = term.current;
        if (!t) {
          return;
        }
        t.reset();
        if (size) {
          t.resize(size.cols, size.rows);
        }
      },
      resize: (c, r) => {
        term.current?.resize(c, r);
      },
    }),
    [],
  );

  return <div ref={el} className="hp-terminal" role="region" aria-label={ariaLabel} />;
}
