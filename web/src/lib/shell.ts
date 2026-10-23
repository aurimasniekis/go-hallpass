/**
 * POSIX shell single-quoting for commands the UI shows to operators to copy (never executed by the UI):
 * `it's` → `'it'\''s'`. Everything inside single quotes is literal, so values cannot inject commands.
 */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/** A user name that is safe to place unquoted in a shell word and a path (`~user`). */
export function isPlainUserName(user: string): boolean {
  return /^[a-z_][a-z0-9_.-]*\$?$/i.test(user);
}
