import { describe, expect, it } from 'vitest';

import {
  barOption,
  isAllZero,
  lineOption,
  seriesSummary,
  seriesTable,
  stateEntries,
  stateSummary,
} from './stats';

const points = [
  { t: '2026-01-01T00:00:00Z', n: 1 },
  { t: '2026-01-01T01:00:00Z', n: 4 },
  { t: '2026-01-01T02:00:00Z', n: 2 },
];

describe('dashboard stats transforms', () => {
  it('summarizes total, peak and latest bucket', () => {
    const s = seriesSummary('requests', points, '24h', 3600);
    expect(s).toMatch(/^7 requests in the last 24 hours\. Peak 4 at .+; latest bucket 2\.$/);
    expect(seriesSummary('requests', [{ t: points[0]?.t ?? '', n: 0 }], '7d', 21600)).toBe(
      'No requests in the last 7 days.',
    );
    expect(seriesSummary('sessions', [], '30d', 86400)).toBe('No sessions in the last 30 days.');
  });

  it('keeps exactly the server buckets in chart and table', () => {
    const opt = lineOption('Requests', points, 3600) as { series: { data: number[] }[] };
    expect(opt.series[0]?.data).toEqual([1, 4, 2]);
    const table = seriesTable(points, 3600, 'Requests');
    expect(table.rows.map((r) => r.n)).toEqual([1, 4, 2]);
    expect(isAllZero(points)).toBe(false);
    expect(isAllZero([])).toBe(true);
  });

  it('orders request states by lifecycle and keeps unknown states', () => {
    const entries = stateEntries({ denied: 1, zeta: 2, pending: 3, approved: 5 });
    expect(entries.map(([s]) => s)).toEqual(['pending', 'approved', 'denied', 'zeta']);
    expect(stateSummary(entries, '24h')).toBe(
      'Requests by current state in the last 24 hours: pending 3, approved 5, denied 1, zeta 2.',
    );
    expect(stateSummary(stateEntries(undefined), '24h')).toBe('No requests in the last 24 hours.');
    const bar = barOption(entries) as { series: { data: number[] }[] };
    expect(bar.series[0]?.data).toEqual([3, 5, 1, 2]);
  });
});
