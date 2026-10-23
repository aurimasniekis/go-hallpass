import { describe, expect, it } from 'vitest';

import {
  bytesToText,
  clampSize,
  decodeBase64,
  decodeExit,
  decodeFooter,
  decodeNotice,
  decodePtyRequest,
  decodeResize,
  decodeSignal,
  PayloadError,
} from './payload';
import { enc, lenBytes, uvarint } from './testutil';

const u8 = (a: number[]) => new Uint8Array(a);

describe('record payload decoders', () => {
  it('decodes terminal.resized (uvarint cols, rows, width, height)', () => {
    expect(decodeResize(u8([...uvarint(132), ...uvarint(43), 0, 0]))).toEqual({
      cols: 132,
      rows: 43,
      widthPx: 0,
      heightPx: 0,
    });
  });

  it('decodes pty.requested with term and modes', () => {
    const p = decodePtyRequest(
      u8([
        ...uvarint(80),
        ...uvarint(24),
        0,
        0,
        ...lenBytes(enc('xterm-256color')),
        ...lenBytes([1, 0, 0, 0, 1]),
      ]),
    );
    expect(p).toMatchObject({ cols: 80, rows: 24, term: 'xterm-256color' });
  });

  it('decodes exit status and exit signal forms', () => {
    expect(decodeExit(u8([0, ...uvarint(130)]))).toEqual({
      status: 130,
      signal: null,
      coreDumped: false,
      message: '',
    });
    expect(decodeExit(u8([1, ...lenBytes(enc('KILL')), 1, ...lenBytes(enc('killed'))]))).toEqual({
      status: null,
      signal: 'KILL',
      coreDumped: true,
      message: 'killed',
    });
  });

  it('decodes signals, notices and footers', () => {
    expect(decodeSignal(enc('INT'))).toBe('INT');
    expect(decodeNotice(u8([...lenBytes(enc('grant.revoked')), ...lenBytes(enc('access ended'))]))).toEqual({
      code: 'grant.revoked',
      message: 'access ended',
    });
    const footer = u8([
      ...uvarint(3),
      ...uvarint(1),
      ...uvarint(3),
      ...lenBytes(enc('closed')),
      ...new Array<number>(32).fill(7),
    ]);
    expect(decodeFooter(footer)).toEqual({ records: 3, firstSeq: 1, lastSeq: 3, endReason: 'closed' });
  });

  it('rejects truncated, trailing, non-minimal and oversized input with PayloadError', () => {
    const bad: (() => unknown)[] = [
      () => decodeResize(u8([80, 24, 0])), // truncated
      () => decodeResize(u8([80, 24, 0, 0, 9])), // trailing
      () => decodeResize(u8([0x80, 0x00, 24, 0, 0])), // non-minimal
      () => decodeResize(u8([0xff, 0xff, 0xff, 0xff, 0x7f, 1, 0, 0])), // exceeds u32
      () => decodeResize(u8(new Array<number>(11).fill(0xff))), // overflow
      () => decodeExit(u8([2])), // unknown kind
      () => decodeExit(u8([1, ...lenBytes(enc('BAD SIG')), 0, 0])), // unprintable signal
      () => decodeExit(u8([1, ...lenBytes(enc('KILL')), 2, 0])), // bad core flag
      () => decodeSignal(enc('')),
      () => decodeSignal(enc('\x1b]0;x')),
      () => decodeNotice(u8([...lenBytes(enc('Bad Code')), 0])),
      () => decodeNotice(u8([...uvarint(5000)])), // length beyond input
      () => decodePtyRequest(u8([80, 24, 0, 0, ...uvarint(300)])), // term too long / truncated
      () => decodeFooter(u8([0, 0, 0, ...lenBytes(enc('x'))])), // missing hash
      () => decodeBase64('***'),
    ];
    for (const fn of bad) {
      expect(fn).toThrow(PayloadError);
    }
  });

  it('decodes base64 and text leniently (invalid UTF-8 becomes U+FFFD)', () => {
    expect(Array.from(decodeBase64('AAEC/w=='))).toEqual([0, 1, 2, 255]);
    expect(bytesToText(u8([0x68, 0xff, 0x69]))).toBe('h�i');
  });

  it('clamps hostile terminal sizes', () => {
    expect(clampSize(100_000, 100_000)).toEqual({ cols: 500, rows: 200 });
    expect(clampSize(0, 0)).toEqual({ cols: 80, rows: 24 });
    expect(clampSize(1, Number.NaN)).toEqual({ cols: 2, rows: 24 });
  });
});
