import type { QueryKey } from '@tanstack/react-query';

import { qk } from '../api/queryKeys';
import type { LiveEvent } from '../api/types';

/**
 * Maps a live event's `resource` to the TanStack Query keys it invalidates (docs/PLAN.md §8.3, §14.4).
 *
 * Keys are prefixes: invalidating `['requests']` refreshes every requests list regardless of filters.
 * Event payloads never carry details, so the UI always refetches through REST.
 *
 * Resource names follow internal/httpapi/sse.go (`request`, `grant`, `access_session`, `channel`,
 * `notification`, `audit_event`, `system`, `policy`). Names are also normalized (case, `-`→`_`, trailing
 * `s`) and a few aliases are accepted, so additive server changes degrade gracefully. Unknown resources return `null`, which the manager treats as
 * "invalidate everything": an over-eager refetch is preferable to showing stale security state.
 */
type KeyBuilder = (event: LiveEvent) => QueryKey[];

const detail = (root: string, id: string | undefined): QueryKey[] => (id ? [[root, id]] : []);

const RESOURCE_KEYS: Record<string, KeyBuilder> = {
  request: (e) => [qk.requests, ...detail('request', e.resource_id), qk.stats, qk.system],
  grant: (e) => [
    qk.grants,
    ...detail('grant', e.resource_id),
    qk.requests,
    qk.accessSessions,
    qk.accessSessionRoot,
    qk.activities,
    qk.system,
  ],
  access_session: (e) => [
    qk.accessSessions,
    ...detail('access-session', e.resource_id),
    qk.activities,
    qk.stats,
  ],
  // activity.started/ended carry the channel ID; the owning session is unknown, so every open session
  // detail (channels, segments, timeline) is refreshed.
  channel: () => [qk.activities, qk.accessSessions, qk.accessSessionRoot, qk.stats, qk.system],
  notification: () => [qk.notificationDeliveries, qk.requests],
  integration: () => [qk.integrations, qk.notificationRoutes],
  audit_event: () => [qk.auditEvents, qk.auditVerify],
  system: () => [qk.system, qk.requests, qk.grants, qk.activities],
  policy: () => [qk.policy, qk.effectiveAccess, qk.system],
  operator: (e) => [qk.operators, ...detail('operator', e.resource_id), qk.me],
  agent: (e) => [qk.agents, ...detail('agent', e.resource_id), qk.effectiveAccess],
  server: (e) => [qk.servers, ...detail('server', e.resource_id), qk.effectiveAccess],
};

const ALIASES: Record<string, string> = {
  session: 'access_session',
  accesssession: 'access_session',
  activity: 'channel',
  audit: 'audit_event',
  notification_delivery: 'notification',
  system_status: 'system',
  policy_rule: 'policy',
};

export function normalizeResource(resource: string): string {
  let r = resource
    .trim()
    .toLowerCase()
    .replace(/[-.\s]/g, '_');
  if (r.endsWith('ies')) {
    r = `${r.slice(0, -3)}y`;
  } else if (r.endsWith('s') && !r.endsWith('ss')) {
    r = r.slice(0, -1);
  }
  return ALIASES[r] ?? r;
}

/** Query keys to invalidate for an event, or `null` when everything should be invalidated. */
export function keysForEvent(event: LiveEvent): QueryKey[] | null {
  if (event.type === 'reset') {
    return null;
  }
  const builder = RESOURCE_KEYS[normalizeResource(event.resource)];
  return builder ? builder(event) : null;
}
