/**
 * Display formatting shared by every page. The API expresses durations as integer seconds
 * (ADR-0031) and timestamps as RFC 3339 UTC strings.
 */

const UNITS = [
  { s: 86_400, short: 'd', long: 'day' },
  { s: 3_600, short: 'h', long: 'hour' },
  { s: 60, short: 'm', long: 'minute' },
  { s: 1, short: 's', long: 'second' },
] as const;

/**
 * Human-readable duration from seconds: `5400` → `1h 30m`. Shows at most `maxParts` non-zero units
 * (default 2), dropping the remainder — so the result never overstates the duration.
 * Returns `—` for null/undefined/negative/non-finite input; `0s` for zero.
 */
export function formatDuration(seconds: number | null | undefined, maxParts = 2): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return '—';
  }
  let rest = Math.floor(seconds);
  if (rest === 0) {
    return '0s';
  }
  const parts: string[] = [];
  for (const unit of UNITS) {
    if (parts.length >= maxParts) {
      break;
    }
    const n = Math.floor(rest / unit.s);
    if (n > 0) {
      parts.push(`${String(n)}${unit.short}`);
      rest -= n * unit.s;
    } else if (parts.length > 0) {
      // Keep units contiguous: 1d 0h 5m is shown as "1d" rather than "1d 5m".
      break;
    }
  }
  return parts.join(' ');
}

/** Long form for screen-reader labels and tooltips: `5400` → `1 hour 30 minutes`. */
export function formatDurationLong(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds) || seconds < 0) {
    return 'unknown duration';
  }
  let rest = Math.floor(seconds);
  if (rest === 0) {
    return '0 seconds';
  }
  const parts: string[] = [];
  for (const unit of UNITS) {
    const n = Math.floor(rest / unit.s);
    if (n > 0) {
      parts.push(`${String(n)} ${unit.long}${n === 1 ? '' : 's'}`);
      rest -= n * unit.s;
    }
  }
  return parts.join(' ');
}

/**
 * Parses `90m`, `1h30m`, `1h 30m`, `2d`, `45s` or a bare number of seconds. Returns seconds, or null
 * when the text is not a duration.
 */
export function parseDuration(text: string): number | null {
  const t = text.trim().toLowerCase();
  if (t === '') {
    return null;
  }
  if (/^\d+$/.test(t)) {
    return Number(t);
  }
  const re = /(\d+)\s*([dhms])/g;
  let total = 0;
  let consumed = '';
  for (const m of t.matchAll(re)) {
    const unit = UNITS.find((u) => u.short === m[2]);
    if (!unit) {
      return null;
    }
    total += Number(m[1]) * unit.s;
    consumed += m[0];
  }
  return consumed.replace(/\s/g, '') === t.replace(/\s/g, '') && consumed !== '' ? total : null;
}

/** Duration units offered by DurationInput. */
export const DURATION_UNITS = [
  { value: 60, label: 'minutes' },
  { value: 3_600, label: 'hours' },
  { value: 86_400, label: 'days' },
] as const;

/** Largest unit that represents `seconds` exactly (minutes when nothing larger fits). */
export function bestDurationUnit(seconds: number): number {
  for (const unit of [...DURATION_UNITS].reverse()) {
    if (seconds > 0 && seconds % unit.value === 0) {
      return unit.value;
    }
  }
  return 60;
}

function parseTime(iso: string | null | undefined): number | null {
  if (!iso) {
    return null;
  }
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/** Local date and time, or `—`. Unparseable input is returned verbatim (it is server data, not HTML). */
export function formatDateTime(iso: string | null | undefined): string {
  const t = parseTime(iso);
  if (t === null) {
    return iso ?? '—';
  }
  return new Date(t).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/** `3 min ago`, `in 2 h`, `just now` relative to `nowMs`. */
export function formatRelative(iso: string | null | undefined, nowMs: number): string {
  const t = parseTime(iso);
  if (t === null) {
    return '—';
  }
  const diff = Math.round((t - nowMs) / 1000);
  const abs = Math.abs(diff);
  if (abs < 10) {
    return 'just now';
  }
  const [value, unit] =
    abs < 60
      ? [abs, 's']
      : abs < 3_600
        ? [Math.floor(abs / 60), 'min']
        : abs < 86_400
          ? [Math.floor(abs / 3_600), 'h']
          : [Math.floor(abs / 86_400), 'd'];
  return diff < 0 ? `${String(value)} ${unit} ago` : `in ${String(value)} ${unit}`;
}

/** Binary byte sizes: `1536` → `1.5 KiB`. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes) || bytes < 0) {
    return '—';
  }
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return i === 0 ? `${String(v)} B` : `${v.toFixed(v < 10 ? 1 : 0)} ${units[i] ?? ''}`;
}

/** Short identifier for dense tables; the full value stays available via title/copy. */
export function shortId(id: string | null | undefined, keep = 10): string {
  if (!id) {
    return '—';
  }
  return id.length <= keep + 1 ? id : `${id.slice(0, keep)}…`;
}

/** Local time of day (`01:55:54 PM`) in the same style as formatDateTime, or `—`. */
export function formatTime(iso: string | null | undefined): string {
  const t = parseTime(iso);
  if (t === null) {
    return iso ?? '—';
  }
  return new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/** Local calendar date (`Oct 24, 2026`) in the same style as formatDateTime, or `—`. */
export function formatDate(iso: string | null | undefined): string {
  const t = parseTime(iso);
  if (t === null) {
    return iso ?? '—';
  }
  return new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
}

/**
 * Go `time.Duration` strings as sent in event data (`30m0s`, `1h30m0s`, `1.5s`) → whole seconds, or
 * null when the text is not such a duration.
 */
export function parseGoDuration(text: string): number | null {
  const t = text.trim();
  if (t === '' || t === '0') {
    return t === '0' ? 0 : null;
  }
  const unit: Record<string, number> = { h: 3600, m: 60, s: 1, ms: 1e-3, us: 1e-6, µs: 1e-6, ns: 1e-9 };
  let total = 0;
  let consumed = '';
  for (const m of t.matchAll(/(\d+(?:\.\d+)?)(h|ms|m|s|us|µs|ns)/g)) {
    total += Number(m[1]) * (unit[m[2] ?? ''] ?? 0);
    consumed += m[0];
  }
  return consumed === t ? Math.floor(total) : null;
}
