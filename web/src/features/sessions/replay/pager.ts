import type { RecordEntry, RecordPage } from '../../../api/types';

/**
 * Loads every record of one recording segment from `GET /recordings/{segment}/records?from_seq=`
 * (≤ 256 KiB per page). Pages are requested while the server reports `more`; records are deduplicated by
 * `seq` (a retried page may overlap) and memory is capped so a huge recording cannot exhaust the tab.
 * Each page access is audited server-side (HP-REC-014), so pages are fetched only on demand.
 */

export type FetchRecordPage = (
  segmentId: string,
  fromSeq: number,
  signal: AbortSignal,
) => Promise<RecordPage>;

export interface PagerLimits {
  /** Maximum decoded payload bytes kept (default 64 MiB). */
  maxBytes?: number;
  /** Maximum records kept (default 500 000). */
  maxRecords?: number;
  /** Maximum pages requested (guards against a server that never stops; default 10 000). */
  maxPages?: number;
}

export interface SegmentLoad {
  segmentId: string;
  records: RecordEntry[];
  /** The server reported the segment complete (finalized and fully read). */
  complete: boolean;
  /** Some page reported the segment incomplete (interrupted recording, missing footer). */
  incomplete: boolean;
  /** Loading stopped at a client limit; the tail was not loaded. */
  truncated: boolean;
  pages: number;
  /** Records dropped as duplicates of an already loaded seq. */
  duplicates: number;
}

/** Decoded size of a base64 string without decoding it. */
export function base64Size(data: string): number {
  const pad = data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0;
  return Math.max(0, Math.floor((data.length * 3) / 4) - pad);
}

export async function loadSegmentRecords(
  segmentId: string,
  fetchPage: FetchRecordPage,
  signal: AbortSignal,
  limits: PagerLimits = {},
  onProgress?: (load: SegmentLoad) => void,
): Promise<SegmentLoad> {
  const maxBytes = limits.maxBytes ?? 64 * 1024 * 1024;
  const maxRecords = limits.maxRecords ?? 500_000;
  const maxPages = limits.maxPages ?? 10_000;
  const load: SegmentLoad = {
    segmentId,
    records: [],
    complete: false,
    incomplete: false,
    truncated: false,
    pages: 0,
    duplicates: 0,
  };
  let fromSeq = 0;
  let lastSeq = -1;
  let bytes = 0;
  for (;;) {
    if (signal.aborted) {
      throw new DOMException('Replay loading aborted', 'AbortError');
    }
    if (load.pages >= maxPages) {
      load.truncated = true;
      break;
    }
    const page = await fetchPage(segmentId, fromSeq, signal);
    load.pages += 1;
    load.incomplete ||= page.incomplete;
    load.complete = page.complete;
    let capped = false;
    for (const rec of page.records) {
      if (rec.seq <= lastSeq) {
        load.duplicates += 1;
        continue;
      }
      const size = base64Size(rec.data);
      if (load.records.length >= maxRecords || bytes + size > maxBytes) {
        capped = true;
        break;
      }
      bytes += size;
      lastSeq = rec.seq;
      load.records.push(rec);
    }
    onProgress?.(load);
    if (capped) {
      load.truncated = true;
      load.complete = false;
      break;
    }
    if (!page.more) {
      break;
    }
    // A page that does not advance would loop forever; treat it as the end of what can be read.
    const next = Math.max(page.next_seq, lastSeq + 1);
    if (next <= fromSeq) {
      load.truncated = true;
      break;
    }
    fromSeq = next;
  }
  return load;
}
