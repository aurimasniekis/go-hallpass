/**
 * Helpers for displaying agent- or destination-provided strings (reasons, command lines, labels).
 *
 * React already escapes text, so HTML cannot be injected; the remaining risks are invisible or
 * reordering characters that make a string read differently than it is (Trojan Source, CVE-2021-42574):
 * bidi overrides/isolates, zero-width characters and C0/C1 controls. These are revealed as visible
 * `<U+XXXX>` markers rather than silently removed, so operators see that something was there.
 */

/* eslint-disable no-control-regex -- matching control characters is the purpose of this pattern. */
const SUSPICIOUS =
  /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]/gu;
/* eslint-enable no-control-regex */

export type UntrustedSegment =
  { kind: 'text'; value: string } | { kind: 'control'; value: string; codePoint: number };

export function codePointLabel(codePoint: number): string {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`;
}

/** Splits text into plain runs and revealed control characters. Tabs and newlines are kept as-is. */
export function segmentUntrusted(text: string): UntrustedSegment[] {
  const segments: UntrustedSegment[] = [];
  let last = 0;
  for (const match of text.matchAll(SUSPICIOUS)) {
    const index = match.index;
    if (index > last) {
      segments.push({ kind: 'text', value: text.slice(last, index) });
    }
    const codePoint = match[0].codePointAt(0) ?? 0;
    segments.push({ kind: 'control', value: `<${codePointLabel(codePoint)}>`, codePoint });
    last = index + match[0].length;
  }
  if (last < text.length) {
    segments.push({ kind: 'text', value: text.slice(last) });
  }
  return segments;
}

/** Plain-string form with control characters revealed (for titles, aria labels, copy). */
export function revealControls(text: string): string {
  return segmentUntrusted(text)
    .map((s) => s.value)
    .join('');
}

/** Truncates on a code-point boundary. */
export function truncateCodePoints(text: string, max: number): { text: string; truncated: boolean } {
  const chars = Array.from(text);
  if (chars.length <= max) {
    return { text, truncated: false };
  }
  return { text: chars.slice(0, max).join(''), truncated: true };
}
