import { describe, expect, it, vi } from 'vitest';

import { base64Size, loadSegmentRecords, type FetchRecordPage } from './pager';
import { enc, page, rec } from './testutil';

const out = 'terminal.output@1';

describe('loadSegmentRecords', () => {
  it('follows next_seq while the server reports more, then stops', async () => {
    const fetchPage = vi.fn<FetchRecordPage>((_seg, from) =>
      Promise.resolve(
        from === 0
          ? page([rec(1, out, enc('a')), rec(2, out, enc('b'))], true)
          : page([rec(3, out, enc('c'))], false),
      ),
    );
    const load = await loadSegmentRecords('seg1', fetchPage, new AbortController().signal);
    expect(fetchPage.mock.calls.map((c) => c[1])).toEqual([0, 3]);
    expect(load.records.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(load).toMatchObject({ complete: true, incomplete: false, truncated: false, pages: 2 });
  });

  it('deduplicates overlapping pages by seq', async () => {
    const pages = [
      page([rec(1, out, enc('a')), rec(2, out, enc('b'))], true, { next_seq: 2 }),
      page([rec(2, out, enc('b')), rec(3, out, enc('c'))], false),
    ];
    const load = await loadSegmentRecords(
      'seg1',
      () => Promise.resolve(pages.shift() ?? page([], false)),
      new AbortController().signal,
    );
    expect(load.records.map((r) => r.seq)).toEqual([1, 2, 3]);
    expect(load.duplicates).toBe(1);
  });

  it('reports incomplete (interrupted) segments', async () => {
    const load = await loadSegmentRecords(
      'seg1',
      () => Promise.resolve(page([rec(1, out, enc('a'))], false, { complete: false, incomplete: true })),
      new AbortController().signal,
    );
    expect(load).toMatchObject({ complete: false, incomplete: true });
  });

  it('stops at the memory cap and marks the load truncated', async () => {
    const fetchPage = vi.fn<FetchRecordPage>((_s, from) =>
      Promise.resolve(
        page([rec(from + 1, out, new Uint8Array(100)), rec(from + 2, out, new Uint8Array(100))], true),
      ),
    );
    const load = await loadSegmentRecords('seg1', fetchPage, new AbortController().signal, { maxBytes: 250 });
    expect(load.records).toHaveLength(2);
    expect(load.truncated).toBe(true);
    expect(load.complete).toBe(false);
  });

  it('stops when the server does not advance', async () => {
    const fetchPage = vi.fn<FetchRecordPage>(() => Promise.resolve(page([], true, { next_seq: 0 })));
    const load = await loadSegmentRecords('seg1', fetchPage, new AbortController().signal);
    expect(fetchPage).toHaveBeenCalledTimes(1);
    expect(load.truncated).toBe(true);
  });

  it('honors abort between pages', async () => {
    const ctrl = new AbortController();
    const fetchPage = vi.fn<FetchRecordPage>(() => {
      ctrl.abort();
      return Promise.resolve(page([rec(1, out, enc('a'))], true));
    });
    await expect(loadSegmentRecords('seg1', fetchPage, ctrl.signal)).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });

  it('computes decoded base64 sizes', () => {
    expect(base64Size('')).toBe(0);
    expect(base64Size('YQ==')).toBe(1);
    expect(base64Size('YWI=')).toBe(2);
    expect(base64Size('YWJj')).toBe(3);
  });
});
