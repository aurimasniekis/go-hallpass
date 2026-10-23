/**
 * `Idempotency-Key` values for non-idempotent POSTs (HP-API-006). A key identifies one *intended*
 * action: callers create it when the operator opens a confirmation (or form) and reuse it when the
 * same action is retried after a network error, so the server never applies it twice.
 */
export function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Fallback for very old test environments; still unpredictable enough to avoid collisions.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
