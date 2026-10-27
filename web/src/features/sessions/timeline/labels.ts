import type { StatusTone } from '../../../ds/StatusBadge';
import { revealControls } from '../../../ds/untrusted';

/** Human labels for timeline event types (internal/access/service.go, schema version 1). */
const LABELS: Record<string, { label: string; tone: StatusTone }> = {
  'request.created': { label: 'Request created', tone: 'info' },
  'request.approved': { label: 'Request approved', tone: 'success' },
  'request.denied': { label: 'Request denied', tone: 'error' },
  'request.expired': { label: 'Request expired', tone: 'neutral' },
  'request.canceled': { label: 'Request canceled', tone: 'neutral' },
  'grant.activated': { label: 'Grant activated', tone: 'success' },
  'grant.expired': { label: 'Grant expired', tone: 'neutral' },
  'grant.revoked': { label: 'Grant revoked', tone: 'error' },
  'grant.clamped': { label: 'Grant shortened', tone: 'warning' },
  'connection.opened': { label: 'Connection opened', tone: 'info' },
  'connection.closed': { label: 'Connection closed', tone: 'neutral' },
  'channel.opened': { label: 'Channel opened', tone: 'success' },
  'channel.exited': { label: 'Channel exited', tone: 'neutral' },
  'channel.failed': { label: 'Channel failed', tone: 'error' },
  'exec.requested': { label: 'Exec requested', tone: 'info' },
  'recording.failed': { label: 'Recording failed', tone: 'error' },
  'access_session.closed': { label: 'Session closed', tone: 'neutral' },
  'destination.exec': { label: 'Destination-reported command', tone: 'warning' },
  'request.approval_recorded': { label: 'Approval recorded', tone: 'info' },
  'git.requested': { label: 'Git operation', tone: 'info' },
  'git.push': { label: 'Git push', tone: 'success' },
  'git.push_refused': { label: 'Git push refused', tone: 'error' },
  'git.transferred': { label: 'Git transfer finished', tone: 'neutral' },
  'file.operation': { label: 'File operation', tone: 'info' },
  'api.request': { label: 'API call', tone: 'info' },
  'file.summary': { label: 'File transfer finished', tone: 'neutral' },
};

export function timelineLabel(type: string): { label: string; tone: StatusTone } {
  return LABELS[type] ?? { label: revealControls(type), tone: 'neutral' };
}

/**
 * Flattens an event's `data` object into display pairs. Values are shown as plain text with hidden and
 * control characters revealed; nested values are JSON-encoded. Nothing is interpreted as markup.
 */
export function timelineFields(data: unknown): { key: string; value: string }[] {
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    return [];
  }
  return Object.entries(data as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => ({
      key: revealControls(key),
      value: revealControls(
        typeof value === 'string'
          ? value
          : typeof value === 'number' || typeof value === 'boolean'
            ? String(value)
            : value === null
              ? 'null'
              : JSON.stringify(value),
      ),
    }));
}

/**
 * Command provenance for timeline events (HP-REC-006): `exec.requested` is the gateway-captured request;
 * `destination.exec` is reported by the destination and unverified. Nothing is ever "verified".
 */
export function timelineProvenance(type: string): 'captured' | 'destination-audit' | null {
  if (type === 'exec.requested') {
    return 'captured';
  }
  if (type === 'destination.exec') {
    return 'destination-audit';
  }
  return null;
}

/** `verified` is never displayed as a field (it is always false and could only mislead). */
export const HIDDEN_FIELDS: ReadonlySet<string> = new Set(['verified', 'provenance']);
