import type { RecordEntry, Segment } from '../../../api/types';
import {
  clampSize,
  decodeBase64,
  decodeExit,
  decodeNotice,
  decodePtyRequest,
  decodeResize,
  decodeSignal,
  bytesToText,
  KNOWN_RECORD_TYPES,
  RECORD,
  type ExitInfo,
  type Notice,
} from './payload';
import type { SegmentLoad } from './pager';

/**
 * Builds one replay track (one SSH channel, HP-REC-010) from its segments' records. Records become
 * time-positioned frames; playback never interprets record content beyond the documented payloads.
 */

export type FrameKind = 'output' | 'stdout' | 'stderr' | 'resize';

export interface Frame {
  /** Track time in ms. */
  t: number;
  seq: number;
  kind: FrameKind;
  bytes?: Uint8Array;
  cols?: number;
  rows?: number;
}

export interface TrackEvent {
  t: number;
  seq: number;
  kind: 'notice' | 'exit' | 'signal' | 'eof';
  notice?: Notice;
  exit?: ExitInfo;
  signal?: string;
  stream?: string;
}

/**
 * Provenance of a command shown for an exec channel (HP-REC-006). `captured`: the exec request the
 * gateway received. `destination-audit` arrives with WP25. `inferred`: derived from keystrokes or output.
 * There is deliberately no `verified` value.
 */
export type CommandProvenance = 'captured' | 'destination-audit' | 'inferred';

export interface TrackCommand {
  text: string;
  provenance: CommandProvenance;
}

export interface Track {
  kind: 'pty' | 'exec';
  frames: Frame[];
  events: TrackEvent[];
  durationMs: number;
  initialSize: { cols: number; rows: number };
  term: string | null;
  command: TrackCommand | null;
  /** terminal.input records present (never played; may contain secrets, HP-REC-005). */
  inputRecords: number;
  unknownRecords: number;
  invalidRecords: number;
  incomplete: boolean;
  truncated: boolean;
}

export interface TrackOptions {
  /** Idle gaps longer than this are shortened to it (ms). 0 disables. */
  idleCapMs?: number;
}

export function buildTrack(
  kind: 'pty' | 'exec',
  parts: readonly { segment: Pick<Segment, 'id' | 'ordinal'>; load: SegmentLoad }[],
  options: TrackOptions = {},
): Track {
  const idleCap = options.idleCapMs ?? 0;
  const track: Track = {
    kind,
    frames: [],
    events: [],
    durationMs: 0,
    initialSize: { cols: 80, rows: 24 },
    term: null,
    command: null,
    inputRecords: 0,
    unknownRecords: 0,
    invalidRecords: 0,
    incomplete: false,
    truncated: false,
  };
  let sizeSet = false;
  let trackStartWall: number | null = null;
  let cursor = 0; // track time of the previous record
  const sorted = [...parts].sort((a, b) => a.segment.ordinal - b.segment.ordinal);

  for (const { load } of sorted) {
    track.incomplete ||= load.incomplete;
    track.truncated ||= load.truncated;
    let segFirstOffset: number | null = null;
    let segBase = cursor;
    let prevRaw = cursor;
    for (const rec of load.records) {
      const wall = Date.parse(rec.time);
      if (trackStartWall === null && Number.isFinite(wall)) {
        trackStartWall = wall;
      }
      if (segFirstOffset === null) {
        segFirstOffset = rec.offset_ms ?? 0;
        // Place the segment by wall-clock distance from the track start, never before the previous one.
        const byWall = trackStartWall !== null && Number.isFinite(wall) ? wall - trackStartWall : cursor;
        segBase = Math.max(cursor, byWall);
        prevRaw = segBase;
      }
      const raw = segBase + Math.max(0, (rec.offset_ms ?? 0) - segFirstOffset);
      let gap = Math.max(0, raw - prevRaw);
      if (idleCap > 0 && gap > idleCap) {
        gap = idleCap;
      }
      prevRaw = raw;
      const t = cursor + gap;
      cursor = t;
      applyRecord(
        track,
        rec,
        t,
        () => {
          sizeSet = true;
        },
        sizeSet,
      );
    }
  }
  track.durationMs = cursor;
  return track;
}

function applyRecord(track: Track, rec: RecordEntry, t: number, markSized: () => void, sized: boolean): void {
  if (!KNOWN_RECORD_TYPES.has(rec.type)) {
    track.unknownRecords += 1;
    return;
  }
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64(rec.data);
  } catch {
    track.invalidRecords += 1;
    return;
  }
  try {
    switch (rec.type) {
      case RECORD.output:
        track.frames.push({ t, seq: rec.seq, kind: 'output', bytes });
        break;
      case RECORD.stdout:
        track.frames.push({ t, seq: rec.seq, kind: 'stdout', bytes });
        break;
      case RECORD.stderr:
        track.frames.push({ t, seq: rec.seq, kind: 'stderr', bytes });
        break;
      case RECORD.input:
        track.inputRecords += 1;
        break;
      case RECORD.ptyRequested: {
        const p = decodePtyRequest(bytes);
        const size = clampSize(p.cols, p.rows);
        track.term = p.term;
        if (!sized) {
          track.initialSize = size;
          markSized();
        } else {
          track.frames.push({ t, seq: rec.seq, kind: 'resize', ...size });
        }
        break;
      }
      case RECORD.resized: {
        const r = decodeResize(bytes);
        const size = clampSize(r.cols, r.rows);
        if (!sized && track.frames.length === 0) {
          track.initialSize = size;
          markSized();
        } else {
          track.frames.push({ t, seq: rec.seq, kind: 'resize', ...size });
        }
        break;
      }
      case RECORD.execRequested:
        // The exec request as received by the gateway: "captured", never "verified" (HP-REC-006).
        track.command ??= { text: bytesToText(bytes), provenance: 'captured' };
        break;
      case RECORD.notice:
        track.events.push({ t, seq: rec.seq, kind: 'notice', notice: decodeNotice(bytes) });
        break;
      case RECORD.exit:
        track.events.push({ t, seq: rec.seq, kind: 'exit', exit: decodeExit(bytes) });
        break;
      case RECORD.signal:
        track.events.push({ t, seq: rec.seq, kind: 'signal', signal: decodeSignal(bytes) });
        break;
      case RECORD.eof:
        track.events.push({ t, seq: rec.seq, kind: 'eof', stream: rec.stream });
        break;
      default:
        // env.accepted and segment.footer carry metadata only; they are not replayed.
        break;
    }
  } catch {
    track.invalidRecords += 1;
  }
}

/** Splits bytes into bounded chunks for terminal writes (HP-UI-013: data fed in bounded chunks). */
export function chunkBytes(bytes: Uint8Array, max = 16 * 1024): Uint8Array[] {
  if (bytes.length <= max) {
    return [bytes];
  }
  const out: Uint8Array[] = [];
  for (let i = 0; i < bytes.length; i += max) {
    out.push(bytes.subarray(i, i + max));
  }
  return out;
}
