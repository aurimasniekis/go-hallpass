import { useCallback, useState } from 'react';

export interface CursorPager {
  /** Cursor for the current page (`undefined` = first page). */
  cursor: string | undefined;
  /** 0-based page number, for display. */
  pageIndex: number;
  hasPrevious: boolean;
  /** Move to the page after the current one, given the server's `next_cursor`. */
  next: (nextCursor: string | null | undefined) => void;
  previous: () => void;
  reset: () => void;
}

/**
 * Cursor pagination state for `{items, next_cursor}` endpoints (docs/PLAN.md §8.1). Cursors are opaque
 * and forward-only, so "previous" pops a stack of the cursors already visited. Changing `resetKey`
 * (typically the serialized filters) returns to the first page.
 */
export function useCursorPager(resetKey: string): CursorPager {
  const [state, setState] = useState<{ key: string; stack: string[] }>({ key: resetKey, stack: [] });
  // Reset during render when the filters change (React's recommended "adjust state on prop change").
  const stack = state.key === resetKey ? state.stack : [];
  if (state.key !== resetKey) {
    setState({ key: resetKey, stack: [] });
  }
  const next = useCallback(
    (nextCursor: string | null | undefined) => {
      if (nextCursor) {
        setState((s) => ({ key: resetKey, stack: [...(s.key === resetKey ? s.stack : []), nextCursor] }));
      }
    },
    [resetKey],
  );
  const previous = useCallback(() => {
    setState((s) => ({ key: s.key, stack: s.stack.slice(0, -1) }));
  }, []);
  const reset = useCallback(() => {
    setState({ key: resetKey, stack: [] });
  }, [resetKey]);
  return {
    cursor: stack.at(-1),
    pageIndex: stack.length,
    hasPrevious: stack.length > 0,
    next,
    previous,
    reset,
  };
}
