import type { RecordEntry, RecordPage } from '../../../api/types';

/** Test helpers: encode payloads the way internal/recording/hprec/payload.go does. */
export function uvarint(n: number): number[] {
  const out: number[] = [];
  let v = n;
  while (v >= 0x80) {
    out.push((v % 128) | 0x80);
    v = Math.floor(v / 128);
  }
  out.push(v);
  return out;
}

export function lenBytes(b: Uint8Array | number[]): number[] {
  const arr = Array.from(b);
  return [...uvarint(arr.length), ...arr];
}

export const enc = (s: string) => new TextEncoder().encode(s);

export function b64(bytes: Uint8Array | number[]): string {
  let bin = '';
  for (const b of Array.from(bytes)) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin);
}

export function rec(
  seq: number,
  type: string,
  data: Uint8Array | number[],
  offsetMs = seq * 100,
  stream = 'pty',
): RecordEntry {
  return {
    seq,
    type,
    data: b64(data),
    offset_ms: offsetMs,
    stream,
    time: new Date(Date.UTC(2026, 0, 1) + offsetMs).toISOString(),
  };
}

export function page(records: RecordEntry[], more: boolean, extra: Partial<RecordPage> = {}): RecordPage {
  const last = records.at(-1)?.seq ?? 0;
  return {
    segment_id: 'seg1',
    records,
    next_seq: last + 1,
    more,
    complete: !more,
    incomplete: false,
    ...extra,
  };
}
