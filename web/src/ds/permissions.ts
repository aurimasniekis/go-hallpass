/**
 * Client-side permission checks for hiding or disabling UI. They are a convenience only:
 * the server authorizes every request (HP-RBAC-*), and a hidden button is not a security control.
 */
export function hasPermissions(
  granted: readonly string[] | undefined,
  required: string | readonly string[],
  mode: 'all' | 'any' = 'all',
): boolean {
  if (!granted) {
    return false;
  }
  const needed = typeof required === 'string' ? [required] : required;
  if (needed.length === 0) {
    return true;
  }
  const set = new Set(granted);
  return mode === 'all' ? needed.every((p) => set.has(p)) : needed.some((p) => set.has(p));
}
