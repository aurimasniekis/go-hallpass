/**
 * Decoders for HPREC1 record payloads as returned by `GET /recordings/{segment}/records` (base64 `data`).
 * Byte layouts follow internal/recording/hprec/payload.go and docs/formats/hprec1.md: integers are minimal
 * unsigned LEB128 uvarints; strings are a uvarint length followed by the bytes. Every decoder rejects
 * truncated, non-minimal, overlong and trailing input by throwing `PayloadError`; callers treat that as a
 * skipped record, never as a crash. Decoded strings are untrusted (agent/destination influenced).
 */

export class PayloadError extends Error {
  constructor(what: string) {
    super(`invalid record payload: ${what}`);
    this.name = 'PayloadError';
  }
}

/** Base64 (standard alphabet, as Go's StdEncoding) to bytes. Throws PayloadError on malformed input. */
export function decodeBase64(data: string): Uint8Array {
  let bin: string;
  try {
    bin = atob(data);
  } catch {
    throw new PayloadError('base64');
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

const MAX_U32 = 0xffff_ffff;

class Reader {
  private pos = 0;
  constructor(private readonly b: Uint8Array) {}

  uvarint(what: string): number {
    let value = 0;
    let scale = 1;
    for (let i = 0; i < 10; i += 1) {
      if (this.pos >= this.b.length) {
        throw new PayloadError(`${what} (truncated)`);
      }
      const byte = this.b[this.pos] ?? 0;
      this.pos += 1;
      value += (byte & 0x7f) * scale;
      if ((byte & 0x80) === 0) {
        if (i > 0 && byte === 0) {
          throw new PayloadError(`${what} (non-minimal)`);
        }
        if (!Number.isSafeInteger(value)) {
          throw new PayloadError(`${what} (too large)`);
        }
        return value;
      }
      scale *= 128;
    }
    throw new PayloadError(`${what} (overflow)`);
  }

  u32(what: string): number {
    const v = this.uvarint(what);
    if (v > MAX_U32) {
      throw new PayloadError(`${what} (exceeds u32)`);
    }
    return v;
  }

  bytes(what: string, maxLen: number): Uint8Array {
    const len = this.uvarint(`${what} length`);
    if (len > maxLen || len > this.b.length - this.pos) {
      throw new PayloadError(`${what} (length)`);
    }
    const out = this.b.subarray(this.pos, this.pos + len);
    this.pos += len;
    return out;
  }

  byte(what: string): number {
    if (this.pos >= this.b.length) {
      throw new PayloadError(`${what} (truncated)`);
    }
    const v = this.b[this.pos] ?? 0;
    this.pos += 1;
    return v;
  }

  remaining(): number {
    return this.b.length - this.pos;
  }

  done(): void {
    if (this.pos !== this.b.length) {
      throw new PayloadError('trailing bytes');
    }
  }
}

const utf8 = new TextDecoder('utf-8', { fatal: false });

/** Lenient UTF-8 decoding: invalid sequences become U+FFFD (the text is displayed, never interpreted). */
export function bytesToText(b: Uint8Array): string {
  return utf8.decode(b);
}

const MAX_TERM = 256;
const MAX_MODES = 4096;
const MAX_SIGNAL = 32;
const MAX_MESSAGE = 4096;
const MAX_CODE = 64;
const MAX_PAYLOAD = 1 << 16;

export interface TermSize {
  cols: number;
  rows: number;
  widthPx: number;
  heightPx: number;
}

export interface PtyRequest extends TermSize {
  term: string;
}

export function decodeResize(b: Uint8Array): TermSize {
  const r = new Reader(b);
  const out = {
    cols: r.u32('cols'),
    rows: r.u32('rows'),
    widthPx: r.u32('width'),
    heightPx: r.u32('height'),
  };
  r.done();
  return out;
}

export function decodePtyRequest(b: Uint8Array): PtyRequest {
  const r = new Reader(b);
  const size = {
    cols: r.u32('cols'),
    rows: r.u32('rows'),
    widthPx: r.u32('width'),
    heightPx: r.u32('height'),
  };
  const term = bytesToText(r.bytes('term', MAX_TERM));
  r.bytes('modes', MAX_MODES);
  r.done();
  return { ...size, term };
}

export interface ExitInfo {
  status: number | null;
  signal: string | null;
  coreDumped: boolean;
  message: string;
}

function printable(s: string): boolean {
  return /^[\x21-\x7e]+$/.test(s);
}

export function decodeExit(b: Uint8Array): ExitInfo {
  const r = new Reader(b);
  const kind = r.byte('exit kind');
  if (kind === 0) {
    const status = r.u32('exit status');
    r.done();
    return { status, signal: null, coreDumped: false, message: '' };
  }
  if (kind !== 1) {
    throw new PayloadError('exit kind');
  }
  const signal = bytesToText(r.bytes('exit signal', MAX_SIGNAL));
  if (!printable(signal)) {
    throw new PayloadError('exit signal name');
  }
  const core = r.byte('core dumped');
  if (core > 1) {
    throw new PayloadError('core dumped flag');
  }
  const message = bytesToText(r.bytes('exit message', MAX_MESSAGE));
  r.done();
  return { status: null, signal, coreDumped: core === 1, message };
}

export function decodeSignal(b: Uint8Array): string {
  const s = bytesToText(b);
  if (s.length === 0 || s.length > MAX_SIGNAL || !printable(s)) {
    throw new PayloadError('signal name');
  }
  return s;
}

export interface Notice {
  code: string;
  message: string;
}

export function decodeNotice(b: Uint8Array): Notice {
  const r = new Reader(b);
  const code = bytesToText(r.bytes('notice code', MAX_CODE));
  const message = bytesToText(r.bytes('notice message', MAX_PAYLOAD));
  r.done();
  if (!/^[a-z0-9_.-]{1,64}$/.test(code)) {
    throw new PayloadError('notice code');
  }
  return { code, message };
}

export interface Footer {
  records: number;
  firstSeq: number;
  lastSeq: number;
  endReason: string;
}

export function decodeFooter(b: Uint8Array): Footer {
  const r = new Reader(b);
  const records = r.uvarint('records');
  const firstSeq = r.uvarint('first_seq');
  const lastSeq = r.uvarint('last_seq');
  const endReason = bytesToText(r.bytes('end_reason', MAX_CODE));
  // The remaining 32 bytes are the plaintext SHA-256; integrity is verified server-side.
  if (r.remaining() !== 32) {
    throw new PayloadError('plaintext_sha256');
  }
  return { records, firstSeq, lastSeq, endReason };
}

/** Record types the UI understands (versioned, HP-REC-001). Others are skipped and counted. */
export const RECORD = {
  execRequested: 'exec.requested@1',
  ptyRequested: 'pty.requested@1',
  envAccepted: 'env.accepted@1',
  output: 'terminal.output@1',
  input: 'terminal.input@1',
  resized: 'terminal.resized@1',
  stdout: 'stdout@1',
  stderr: 'stderr@1',
  signal: 'signal@1',
  eof: 'eof@1',
  exit: 'exit@1',
  notice: 'gateway.notice@1',
  footer: 'segment.footer@1',
} as const;

export const KNOWN_RECORD_TYPES: ReadonlySet<string> = new Set(Object.values(RECORD));

/** Terminal sizes from recordings are clamped before they reach xterm (a hostile resize cannot exhaust memory). */
export function clampSize(cols: number, rows: number): { cols: number; rows: number } {
  const c = Number.isFinite(cols) ? Math.round(cols) : 80;
  const r = Number.isFinite(rows) ? Math.round(rows) : 24;
  return { cols: Math.min(500, Math.max(2, c || 80)), rows: Math.min(200, Math.max(1, r || 24)) };
}
