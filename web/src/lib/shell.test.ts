import { describe, expect, it } from 'vitest';

import { isPlainUserName, shellQuote } from './shell';

describe('shellQuote', () => {
  it('single-quotes and escapes embedded quotes', () => {
    expect(shellQuote('abc')).toBe("'abc'");
    expect(shellQuote("it's")).toBe("'it'\\''s'");
    expect(shellQuote('$(rm -rf /) `x`')).toBe("'$(rm -rf /) `x`'");
  });

  it('accepts only plain user names', () => {
    expect(isPlainUserName('deploy')).toBe(true);
    expect(isPlainUserName('svc-app.1')).toBe(true);
    expect(isPlainUserName('a b')).toBe(false);
    expect(isPlainUserName('x;rm')).toBe(false);
    expect(isPlainUserName('')).toBe(false);
  });
});
