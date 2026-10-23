import type { StatusTone } from '../ds/StatusBadge';
import { revealControls } from '../ds/untrusted';

/**
 * Human words for gateway close/end reason codes (internal/sshproxy, internal/access). The codes are
 * stable machine values; unknown ones are shown with underscores replaced, never dropped.
 */
const REASONS: Record<string, string> = {
  exit: 'Exited',
  failed_before_start: 'Failed before it started',
  agent_disconnected: 'Agent disconnected',
  client_closed: 'Agent closed the connection',
  idle_timeout: 'Idle timeout',
  recording_failed: 'Recording failed',
  destination_keepalive_timeout: 'Destination stopped responding',
  destination_keepalive_failed: 'Destination connection lost',
  destination_closed: 'Destination closed the channel',
  expired: 'Grant expired',
  operator: 'Revoked by an operator',
  terminated: 'Terminated by an operator',
  agent: 'Canceled by the agent',
  policy_changed: 'Policy changed',
  agent_disabled: 'Agent disabled',
  key_revoked: 'Agent key revoked',
  target_disabled: 'Server or role disabled',
  credential_revoked: 'Login credential revoked',
  lockdown: 'Lockdown',
  shutdown: 'Gateway shut down',
  process_restart: 'Gateway restarted (interrupted)',
};

/** `failed_before_start` → `Failed before it started`; unknown codes become sentence case. */
export function reasonText(code: string | null | undefined): string | null {
  if (code === null || code === undefined || code === '') {
    return null;
  }
  const known = REASONS[code];
  if (known) {
    return known;
  }
  const words = revealControls(code).replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** Gateway exit codes an agent sees when the gateway (not the destination) ended a channel. */
export const GATEWAY_EXIT_CODES: Readonly<Record<number, string>> = {
  80: 'internal error',
  81: 'usage error',
  82: 'not found or not permitted',
  83: 'denied',
  84: 'request expired',
  85: 'request canceled',
  86: 'wait timed out',
  87: 'access ended',
  88: 'destination unavailable',
  89: 'limit exceeded',
  90: 'input required',
};

/** Codes listed in the short legend next to channel tables. */
export const GATEWAY_EXIT_LEGEND = [80, 87, 88, 89, 90] as const;

export function gatewayExitText(code: number | null | undefined): string | null {
  if (code === null || code === undefined) {
    return null;
  }
  const meaning = GATEWAY_EXIT_CODES[code];
  return meaning ? `${String(code)} (${meaning})` : String(code);
}

export interface ChannelEnd {
  /** Readable reason, e.g. "Failed before it started". Null while the channel is live. */
  reason: string | null;
  /** Classified detail from the gateway, e.g. "destination host key changed". */
  detail: string | null;
  /** Gateway exit code with its meaning, e.g. "88 (destination unavailable)". */
  gatewayExit: string | null;
  /** Destination exit status or signal. */
  exit: string | null;
  tone: StatusTone;
}

export interface ChannelEndInput {
  state: string;
  close_reason?: string | undefined;
  close_detail?: string | undefined;
  gateway_exit_code?: number | null | undefined;
  exit_status?: number | null | undefined;
  exit_signal?: string | undefined;
}

/**
 * Why a channel ended, from the fields the API reports. `close_detail` and `gateway_exit_code` are newer
 * fields: when absent, only the reason code is shown.
 */
export function describeChannelEnd(c: ChannelEndInput): ChannelEnd {
  const reason = reasonText(c.close_reason);
  const rawDetail = c.close_detail ? revealControls(c.close_detail) : null;
  // The gateway repeats simple reasons as the detail ("agent disconnected"); show them once.
  const detail = rawDetail && rawDetail.toLowerCase() !== reason?.toLowerCase() ? rawDetail : null;
  const exit = c.exit_signal
    ? `signal ${revealControls(c.exit_signal)}`
    : c.exit_status !== null && c.exit_status !== undefined
      ? `status ${String(c.exit_status)}`
      : null;
  const failed = c.state === 'failed';
  const gatewayEnded = (c.gateway_exit_code ?? 0) !== 0;
  const nonZero = (c.exit_status ?? 0) !== 0 || Boolean(c.exit_signal);
  return {
    reason,
    detail,
    gatewayExit: gatewayExitText(c.gateway_exit_code),
    exit,
    tone: failed
      ? 'error'
      : gatewayEnded || nonZero || (c.close_reason && c.close_reason !== 'exit')
        ? 'warning'
        : 'neutral',
  };
}

/** `exec`, `shell (PTY)`, `shell (no PTY)`. */
export function channelKind(c: { kind: string; pty: boolean }): string {
  if (c.kind === 'shell') {
    return c.pty ? 'shell (PTY)' : 'shell (no PTY)';
  }
  return c.pty ? `${c.kind} (PTY)` : c.kind;
}
