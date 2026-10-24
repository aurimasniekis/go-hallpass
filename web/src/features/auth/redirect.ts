/**
 * Post-login redirect target validation. Only same-origin relative paths are accepted, preventing open
 * redirects through `/login?next=https://evil.example` or protocol-relative `//evil.example`, also after
 * normalization (`/.//evil.example`, SR-25).
 */
const AUTH_PAGES = ['/login', '/setup', '/recover'];

// Rejecting control characters is the point of this pattern.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

// "." and ".." path segments, also percent-encoded. URL normalization resolves them, so "/.//evil.example" would
// come out as the protocol-relative "//evil.example" (SR-25); no UI route needs them.
const DOT_SEGMENT = /(^|\/)(\.|%2e){1,2}(\/|$)/i;

export function safeNextPath(next: unknown, origin: string = window.location.origin): string {
  if (typeof next !== 'string' || next === '' || next.length > 2048) {
    return '/';
  }
  // Must be an absolute path, not protocol-relative, without backslashes or control characters.
  if (!next.startsWith('/') || next.startsWith('//') || next.includes('\\') || CONTROL_CHARS.test(next)) {
    return '/';
  }
  const rawPath = next.split(/[?#]/, 1)[0] ?? '';
  if (DOT_SEGMENT.test(rawPath)) {
    return '/';
  }
  let url: URL;
  try {
    url = new URL(next, origin);
  } catch {
    return '/';
  }
  // The returned value is the normalized path; it must still not be protocol-relative.
  if (url.origin !== origin || url.pathname.startsWith('//')) {
    return '/';
  }
  if (AUTH_PAGES.includes(url.pathname) || url.pathname.startsWith('/api/')) {
    return '/';
  }
  return `${url.pathname}${url.search}${url.hash}`;
}
