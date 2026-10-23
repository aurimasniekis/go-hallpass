import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { useCursorPager } from './useCursorPager';

describe('useCursorPager', () => {
  it('walks forward with server cursors and back through the visited stack', () => {
    const { result } = renderHook(() => useCursorPager('f1'));
    expect(result.current.cursor).toBeUndefined();
    act(() => {
      result.current.next('c1');
    });
    act(() => {
      result.current.next('c2');
    });
    expect(result.current.cursor).toBe('c2');
    expect(result.current.pageIndex).toBe(2);
    act(() => {
      result.current.previous();
    });
    expect(result.current.cursor).toBe('c1');
    act(() => {
      result.current.next(null);
    });
    expect(result.current.cursor).toBe('c1');
  });

  it('returns to the first page when the filters change', () => {
    const { result, rerender } = renderHook(({ key }) => useCursorPager(key), { initialProps: { key: 'a' } });
    act(() => {
      result.current.next('c1');
    });
    rerender({ key: 'b' });
    expect(result.current.cursor).toBeUndefined();
    expect(result.current.hasPrevious).toBe(false);
  });
});
