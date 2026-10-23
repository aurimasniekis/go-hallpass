import type { EChartsCoreOption } from 'echarts/core';

import type { StatsOverview } from '../../api/types';

/**
 * Pure transforms from `GET /stats/overview` into chart options, accessible summaries and table rows
 * (HP-UI-009). No synthetic points are ever added: the chart shows exactly the server's buckets.
 */

export interface SeriesPoint {
  t: string;
  n: number;
}

/** Bucket label: time of day for hourly buckets, date otherwise. */
export function bucketLabel(iso: string, bucketSeconds: number): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) {
    return iso;
  }
  const d = new Date(t);
  if (bucketSeconds < 86_400) {
    return d.toLocaleString(undefined, {
      month: 'short',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  }
  return d.toLocaleDateString(undefined, { month: 'short', day: '2-digit' });
}

export function seriesTotal(points: readonly SeriesPoint[]): number {
  return points.reduce((sum, p) => sum + p.n, 0);
}

export function isAllZero(points: readonly SeriesPoint[]): boolean {
  return points.every((p) => p.n === 0);
}

const RANGE_TEXT: Record<string, string> = {
  '24h': 'the last 24 hours',
  '7d': 'the last 7 days',
  '30d': 'the last 30 days',
};

export function rangeText(range: string): string {
  return RANGE_TEXT[range] ?? `range ${range}`;
}

/** Plain-language summary: total, peak bucket and latest bucket. */
export function seriesSummary(
  noun: string,
  points: readonly SeriesPoint[],
  range: string,
  bucketSeconds: number,
): string {
  if (points.length === 0 || isAllZero(points)) {
    return `No ${noun} in ${rangeText(range)}.`;
  }
  const total = seriesTotal(points);
  let peak = points[0] ?? { t: '', n: 0 };
  for (const p of points) {
    if (p.n > peak.n) {
      peak = p;
    }
  }
  const latest = points[points.length - 1] ?? peak;
  return (
    `${String(total)} ${noun} in ${rangeText(range)}. ` +
    `Peak ${String(peak.n)} at ${bucketLabel(peak.t, bucketSeconds)}; ` +
    `latest bucket ${String(latest.n)}.`
  );
}

export function lineOption(
  name: string,
  points: readonly SeriesPoint[],
  bucketSeconds: number,
): EChartsCoreOption {
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 16, top: 16, bottom: 28 },
    xAxis: { type: 'category', data: points.map((p) => bucketLabel(p.t, bucketSeconds)) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ name, type: 'line', data: points.map((p) => p.n) }],
  };
}

export function seriesTable(points: readonly SeriesPoint[], bucketSeconds: number, valueTitle: string) {
  return {
    columns: [
      { key: 'bucket', title: 'Bucket start' },
      { key: 'n', title: valueTitle },
    ],
    rows: points.map((p) => ({ bucket: bucketLabel(p.t, bucketSeconds), n: p.n })),
  };
}

/** Request states in lifecycle order; unknown states from additive API changes are appended. */
const STATE_ORDER = ['pending', 'approved', 'denied', 'expired', 'canceled'];

export function stateEntries(byState: StatsOverview['requests_by_state']): [string, number][] {
  const entries = Object.entries(byState ?? {});
  return entries.sort(([a], [b]) => {
    const ia = STATE_ORDER.indexOf(a);
    const ib = STATE_ORDER.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib) || a.localeCompare(b);
  });
}

export function stateSummary(entries: readonly [string, number][], range: string): string {
  const total = entries.reduce((s, [, n]) => s + n, 0);
  if (total === 0) {
    return `No requests in ${rangeText(range)}.`;
  }
  return `Requests by current state in ${rangeText(range)}: ${entries.map(([s, n]) => `${s} ${String(n)}`).join(', ')}.`;
}

export function barOption(entries: readonly [string, number][]): EChartsCoreOption {
  return {
    tooltip: { trigger: 'axis' },
    grid: { left: 40, right: 16, top: 16, bottom: 28 },
    xAxis: { type: 'category', data: entries.map(([s]) => s) },
    yAxis: { type: 'value', minInterval: 1 },
    series: [{ name: 'Requests', type: 'bar', data: entries.map(([, n]) => n) }],
  };
}
