/**
 * Post-login redirect target validation. Only same-origin relative paths are accepted, preventing open
 * redirects through `/login?next=https://evil.example` or protocol-relative `//evil.example`.
 */
const AUTH_PAGES = ['/login', '/setup'];

// Rejecting control characters is the point of this pattern.
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;

export function safeNextPath(next: unknown, origin: string = window.location.origin): string {
  if (typeof next !== 'string' || next === '' || next.length > 2048) {
    return '/';
  }
  // Must be an absolute path, not protocol-relative, without backslashes or control characters.
  if (!next.startsWith('/') || next.startsWith('//') || next.includes('\\') || CONTROL_CHARS.test(next)) {
    return '/';
  }
  let url: URL;
  try {
    url = new URL(next, origin);
  } catch {
    return '/';
  }
  if (url.origin !== origin) {
    return '/';
  }
  if (AUTH_PAGES.includes(url.pathname) || url.pathname.startsWith('/api/')) {
    return '/';
  }
  return `${url.pathname}${url.search}${url.hash}`;
}
