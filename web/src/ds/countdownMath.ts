/**
 * Countdown math (HP-UI-011). Remaining time is computed against *server* time:
 * `serverNow = clientNow + offsetMs`, where `offsetMs = serverTime - clientTime` comes from
 * src/stores/clock.ts. A skewed workstation clock therefore does not change displayed lifetimes.
 */

export function serverNow(clientNowMs: number, offsetMs: number): number {
  return clientNowMs + offsetMs;
}

/** Milliseconds until `deadline` (RFC 3339 string or epoch ms) in server time; null if unparseable. */
export function remainingMs(deadline: string | number, clientNowMs: number, offsetMs: number): number | null {
  const target = typeof deadline === 'number' ? deadline : Date.parse(deadline);
  if (!Number.isFinite(target)) {
    return null;
  }
  return target - serverNow(clientNowMs, offsetMs);
}

const pad = (n: number) => String(n).padStart(2, '0');

/**
 * Formats a remaining duration. Rounds *down* to whole seconds so the display never claims more time
 * than is left. Returns null once expired.
 */
export function formatRemaining(ms: number): string | null {
  if (ms <= 0) {
    return null;
  }
  const total = Math.floor(ms / 1000);
  const days = Math.floor(total / 86_400);
  const hours = Math.floor((total % 86_400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (days > 0) {
    return `${String(days)}d ${pad(hours)}h ${pad(minutes)}m`;
  }
  if (hours > 0) {
    return `${String(hours)}h ${pad(minutes)}m ${pad(seconds)}s`;
  }
  return `${String(minutes)}m ${pad(seconds)}s`;
}
