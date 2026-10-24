import { describe, expect, it } from 'vitest';

import { passwordByteLength, validatePasswordLength } from './password';
import { safeNextPath } from './redirect';

const origin = 'https://hallpass.example';

describe('safeNextPath', () => {
  it('keeps same-origin relative paths', () => {
    expect(safeNextPath('/requests?state=pending#x', origin)).toBe('/requests?state=pending#x');
    expect(safeNextPath('/sessions/abc', origin)).toBe('/sessions/abc');
  });

  it.each([
    'https://evil.example/',
    '//evil.example/path',
    '/\\evil.example',
    // eslint-disable-next-line no-script-url -- asserting that script URLs are rejected.
    'javascript:alert(1)',
    'requests',
    '/login',
    '/setup?token=x',
    '/api/v1/auth/logout',
    '/ok\u0000',
    // SR-25: dot segments that normalize to a protocol-relative path.
    '/.//evil.example',
    '/x/..//evil.example/p',
    '/%2e//evil.example',
    '/%2E%2E//evil.example',
    '/./api/v1/me',
    '',
    undefined,
    42,
  ])('rejects %j', (value) => {
    expect(safeNextPath(value, origin)).toBe('/');
  });

  it('never returns a protocol-relative path', () => {
    for (const p of ['/.//evil.example', '/a/b/../..//evil.example', '/%2e%2e//x', '/..//x']) {
      expect(safeNextPath(p, origin).startsWith('//')).toBe(false);
    }
  });
});

describe('password length rule', () => {
  it('measures NFKC-normalized UTF-8 bytes', () => {
    expect(passwordByteLength('abc')).toBe(3);
    expect(passwordByteLength('é')).toBe(2);
    // U+FB01 (\uFB01 ligature) normalizes to "fi" under NFKC.
    expect(passwordByteLength('\uFB01')).toBe(2);
  });

  it('enforces 12–1024 bytes without truncation', () => {
    expect(validatePasswordLength('short')).toMatch(/at least 12/);
    expect(validatePasswordLength('correct horse battery')).toBeNull();
    expect(validatePasswordLength('x'.repeat(1025))).toMatch(/at most 1024/);
    expect(validatePasswordLength('x'.repeat(1024))).toBeNull();
  });
});

describe('sso error messages', () => {
  it('explains the recent-sign-in requirement for self-service linking (SR-10)', async () => {
    const { ssoErrorMessage } = await import('./sso');
    expect(ssoErrorMessage('reauth_required')).toMatch(/recent sign-in/);
  });
});
