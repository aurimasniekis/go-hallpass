import { useSyncExternalStore } from 'react';

/** Phones: tables become cards. Matches Ant Design's `md` breakpoint (768 px). */
export const NARROW_QUERY = '(max-width: 767.98px)';
/** Phones and small tablets: the sidebar becomes a drawer. Matches Ant Design's `lg` breakpoint (992 px). */
export const COMPACT_SHELL_QUERY = '(max-width: 991.98px)';

/**
 * Whether a media query matches, kept up to date. Queries are written as max-width so that environments without
 * real media queries (tests) get the desktop layout.
 */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
        return () => undefined;
      }
      const mql = window.matchMedia(query);
      mql.addEventListener('change', onChange);
      return () => {
        mql.removeEventListener('change', onChange);
      };
    },
    () =>
      typeof window !== 'undefined' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia(query).matches,
    () => false,
  );
}
