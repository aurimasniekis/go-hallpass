import { createHmac } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

import { stateFile } from './env';

/**
 * RFC 6238 TOTP (SHA-1, 30 s, 6 digits) for driving the real enrollment and MFA flows in E2E tests.
 * Test-only: the product verifies codes server-side with Go's standard library.
 */
export function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.replace(/=+$/, '').replace(/\s/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) {
      throw new Error(`invalid base32 character ${ch}`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function totp(secretBase32: string, at = Date.now(), stepSeconds = 30, digits = 6): string {
  const counter = Math.floor(at / 1000 / stepSeconds);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', base32Decode(secretBase32)).update(msg).digest();
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits;
  return String(code).padStart(digits, '0');
}

/**
 * A code for a time step the server has not seen yet. The server rejects a reused step (replay
 * protection), so consecutive MFA prompts — also across test runs and workers — wait for the next step.
 * The last used step is kept in the gitignored E2E state directory.
 */
export async function freshTotp(secretBase32: string): Promise<string> {
  const file = stateFile('totp-last-step');
  let lastStep = -1;
  try {
    lastStep = Number(readFileSync(file, 'utf8'));
  } catch {
    // first use
  }
  for (;;) {
    const step = Math.floor(Date.now() / 30_000);
    if (step > lastStep) {
      writeFileSync(file, String(step));
      return totp(secretBase32);
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
}
