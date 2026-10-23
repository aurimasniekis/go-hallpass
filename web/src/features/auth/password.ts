/** Password length rule from docs/PLAN.md §12.2: NFKC-normalize, then 12–1024 UTF-8 bytes. Never truncated. */
export const PASSWORD_MIN_BYTES = 12;
export const PASSWORD_MAX_BYTES = 1024;

export function passwordByteLength(password: string): number {
  return new TextEncoder().encode(password.normalize('NFKC')).length;
}

/** Returns an error message, or null when the password satisfies the length rule. */
export function validatePasswordLength(password: string): string | null {
  const n = passwordByteLength(password);
  if (n < PASSWORD_MIN_BYTES) {
    return `Use at least ${String(PASSWORD_MIN_BYTES)} characters.`;
  }
  if (n > PASSWORD_MAX_BYTES) {
    return `Use at most ${String(PASSWORD_MAX_BYTES)} bytes; longer passwords are rejected, not truncated.`;
  }
  return null;
}
