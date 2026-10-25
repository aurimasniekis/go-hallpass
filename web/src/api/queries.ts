import { queryOptions } from '@tanstack/react-query';

import { api } from './client';
import { ApiError } from './errors';
import type { Operation, QueryOf } from './endpoints';
import { qk } from './queryKeys';

/**
 * Query option factories for every read endpoint in api/openapi.yaml. Pages use these (never ad-hoc
 * keys) so live-event invalidation (src/sse/invalidation.ts) reaches them.
 */

export type RequestFilters = QueryOf<Operation<'/api/v1/requests', 'get'>>;
export type GrantFilters = QueryOf<Operation<'/api/v1/grants', 'get'>>;
export type SessionFilters = QueryOf<Operation<'/api/v1/access-sessions', 'get'>>;
export type AuditFilters = QueryOf<Operation<'/api/v1/audit-events', 'get'>>;
export type StatsRange = NonNullable<QueryOf<Operation<'/api/v1/stats/overview', 'get'>>['range']>;
export type DeliveryState = NonNullable<
  QueryOf<Operation<'/api/v1/notification-deliveries', 'get'>>['state']
>;
export type GroupKind = NonNullable<QueryOf<Operation<'/api/v1/groups', 'get'>>['kind']>;

/** Drops empty filter values so `{state: ''}` and `{}` share a cache entry and a URL. */
export function compactFilters<T extends object>(filters: T): Partial<T> {
  const out: Partial<T> = {};
  for (const [k, v] of Object.entries(filters) as [keyof T, T[keyof T]][]) {
    if (v !== undefined && v !== null && v !== '') {
      out[k] = v;
    }
  }
  return out;
}

// ---- self and auth

export const meQueryOptions = () =>
  queryOptions({
    queryKey: qk.me,
    queryFn: ({ signal }) => api.getMe({ signal }),
    staleTime: 60_000,
  });

export const authConfigQueryOptions = () =>
  queryOptions({
    queryKey: qk.authConfig,
    queryFn: ({ signal }) => api.getAuthConfig({ signal }),
    staleTime: 5 * 60_000,
  });

export const mySessionsQueryOptions = () =>
  queryOptions({
    queryKey: qk.mySessions,
    queryFn: ({ signal }) => api.call('get', '/api/v1/me/sessions', { signal }),
  });

export const myIdentitiesQueryOptions = () =>
  queryOptions({
    queryKey: qk.myIdentities,
    queryFn: ({ signal }) => api.call('get', '/api/v1/me/identities', { signal }),
  });

// ---- access

export const requestListQueryOptions = (filters: RequestFilters) =>
  queryOptions({
    queryKey: qk.requestList(compactFilters(filters)),
    queryFn: ({ signal }) => api.call('get', '/api/v1/requests', { query: compactFilters(filters), signal }),
  });

export const requestQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.request(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/requests/{id}', { path: { id }, signal }),
  });

export const grantListQueryOptions = (filters: GrantFilters) =>
  queryOptions({
    queryKey: qk.grantList(compactFilters(filters)),
    queryFn: ({ signal }) => api.call('get', '/api/v1/grants', { query: compactFilters(filters), signal }),
  });

export const grantQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.grant(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/grants/{id}', { path: { id }, signal }),
  });

export const sessionListQueryOptions = (filters: SessionFilters) =>
  queryOptions({
    queryKey: qk.accessSessionList(compactFilters(filters)),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/access-sessions', { query: compactFilters(filters), signal }),
  });

export const sessionQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.accessSession(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/access-sessions/{id}', { path: { id }, signal }),
  });

export const sessionChannelsQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.sessionChannels(id),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/access-sessions/{id}/channels', { path: { id }, signal }),
  });

export const sessionSegmentsQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.sessionSegments(id),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/access-sessions/{id}/segments', { path: { id }, signal }),
  });

/** Live channels; with `endedSince` (seconds) also channels that ended within that window. */
export const activitiesQueryOptions = (endedSince?: number) =>
  queryOptions({
    queryKey: qk.activityList(endedSince),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/activities', {
        ...(endedSince ? { query: { ended_since: endedSince } } : {}),
        signal,
      }),
  });

// ---- inventory

export const agentsQueryOptions = () =>
  queryOptions({
    queryKey: qk.agents,
    queryFn: ({ signal }) => api.call('get', '/api/v1/agents', { signal }),
  });

/** Every agent including deleted ones, only for naming agents in history (sessions, requests, audit). */
export const agentNamesQueryOptions = () =>
  queryOptions({
    queryKey: [...qk.agents, { include_deleted: true }] as const,
    queryFn: ({ signal }) => api.call('get', '/api/v1/agents', { query: { include_deleted: true }, signal }),
  });

export const agentQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.agent(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/agents/{id}', { path: { id }, signal }),
  });

export const agentEffectiveAccessQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.agentEffectiveAccess(id),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/agents/{id}/effective-access', { path: { id }, signal }),
  });

export const groupsQueryOptions = (kind?: GroupKind) =>
  queryOptions({
    queryKey: qk.groupList(kind),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/groups', { ...(kind ? { query: { kind } } : {}), signal }),
  });

export const serversQueryOptions = () =>
  queryOptions({
    queryKey: qk.servers,
    queryFn: ({ signal }) => api.call('get', '/api/v1/servers', { signal }),
  });

/** Every server including deleted ones, only for naming servers in history (sessions, requests, audit). */
export const serverNamesQueryOptions = () =>
  queryOptions({
    queryKey: [...qk.servers, { include_deleted: true }] as const,
    queryFn: ({ signal }) => api.call('get', '/api/v1/servers', { query: { include_deleted: true }, signal }),
  });

export const serverQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.server(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/servers/{id}', { path: { id }, signal }),
  });

export const serverEffectiveAccessQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.serverEffectiveAccess(id),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/servers/{id}/effective-access', { path: { id }, signal }),
  });

export const hostIdentitiesQueryOptions = (serverId: string) =>
  queryOptions({
    queryKey: qk.hostIdentities(serverId),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/servers/{id}/host-identities', { path: { id: serverId }, signal }),
  });

export const serverRolesQueryOptions = (serverId: string) =>
  queryOptions({
    queryKey: qk.serverRoles(serverId),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/servers/{id}/roles', { path: { id: serverId }, signal }),
  });

export const roleQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.role(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/roles/{id}', { path: { id }, signal }),
    // Role names are looked up from many tables; they change rarely and SSE carries no role events.
    staleTime: 5 * 60_000,
  });

export const credentialsQueryOptions = (roleId: string) =>
  queryOptions({
    queryKey: qk.credentials(roleId),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/roles/{id}/credentials', { path: { id: roleId }, signal }),
  });

export const userCAsQueryOptions = () =>
  queryOptions({
    queryKey: qk.userCAs,
    queryFn: ({ signal }) => api.call('get', '/api/v1/user-cas', { signal }),
  });

// ---- policy

export const policyRulesQueryOptions = () =>
  queryOptions({
    queryKey: qk.policyRules,
    queryFn: ({ signal }) => api.call('get', '/api/v1/policy/rules', { signal }),
  });

export const approverRulesQueryOptions = () =>
  queryOptions({
    queryKey: qk.approverRules,
    queryFn: ({ signal }) => api.call('get', '/api/v1/policy/approver-rules', { signal }),
  });

export const policyVersionQueryOptions = () =>
  queryOptions({
    queryKey: qk.policyVersion,
    queryFn: ({ signal }) => api.call('get', '/api/v1/policy/version', { signal }),
  });

/** Operators owning an agent (policy.read). */
export const agentOwnersQueryOptions = (agentId: string) =>
  queryOptions({
    queryKey: qk.agentOwners(agentId),
    queryFn: ({ signal }) => api.call('get', '/api/v1/agents/{id}/owners', { path: { id: agentId }, signal }),
  });

/** Whether agent owners are barred from approving their own agents' requests (policy.read). */
export const selfApprovalQueryOptions = () =>
  queryOptions({
    queryKey: qk.selfApproval,
    queryFn: ({ signal }) => api.call('get', '/api/v1/policy/self-approval', { signal }),
  });

// ---- operators

export const operatorsQueryOptions = () =>
  queryOptions({
    queryKey: qk.operators,
    queryFn: ({ signal }) => api.call('get', '/api/v1/operators', { signal }),
  });

export const operatorQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.operator(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/operators/{id}', { path: { id }, signal }),
  });

export const operatorSessionsQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.operatorSessions(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/operators/{id}/sessions', { path: { id }, signal }),
  });

export const operatorIdentitiesQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.operatorIdentities(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/operators/{id}/identities', { path: { id }, signal }),
  });

// ---- audit

export const auditListQueryOptions = (filters: AuditFilters) =>
  queryOptions({
    queryKey: qk.auditList(compactFilters(filters)),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/audit-events', { query: compactFilters(filters), signal }),
  });

// ---- SSO settings

export const oidcProvidersQueryOptions = () =>
  queryOptions({
    queryKey: qk.oidcProviders,
    queryFn: ({ signal }) => api.call('get', '/api/v1/oidc-providers', { signal }),
  });

export const oidcProviderQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.oidcProvider(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/oidc-providers/{id}', { path: { id }, signal }),
  });

export const oidcMappingsQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.oidcMappings(id),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/oidc-providers/{id}/mappings', { path: { id }, signal }),
  });

export const oidcTestLoginQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.oidcTestLogin(id),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/oidc-providers/{id}/test-login', { path: { id }, signal }),
    staleTime: Infinity,
  });

export const authSettingsQueryOptions = () =>
  queryOptions({
    queryKey: qk.authSettings,
    queryFn: ({ signal }) => api.call('get', '/api/v1/settings/auth', { signal }),
  });

// ---- system

export const systemStatusQueryOptions = () =>
  queryOptions({
    queryKey: qk.systemStatus,
    queryFn: ({ signal }) => api.call('get', '/api/v1/system/status', { signal }),
  });

/** Remote (object storage) backup status: configured, last runs, next run (system.read). */
export const backupStatusQueryOptions = () =>
  queryOptions({
    queryKey: qk.backupStatus,
    queryFn: ({ signal }) => api.call('get', '/api/v1/system/backups', { signal }),
  });

/** The backup target, or null when none is configured. */
export const backupTargetQueryOptions = () =>
  queryOptions({
    queryKey: qk.backupTarget,
    queryFn: async ({ signal }) => {
      try {
        return await api.call('get', '/api/v1/system/backups/target', { signal });
      } catch (e) {
        if (e instanceof ApiError && e.status === 404) {
          return null;
        }
        throw e;
      }
    },
  });

/** The newest backup runs. */
export const backupRunsQueryOptions = () =>
  queryOptions({
    queryKey: qk.backupRuns,
    queryFn: async ({ signal }) =>
      (await api.call('get', '/api/v1/system/backups/runs', { query: { limit: 50 }, signal })).items,
  });

/** fail2ban-style bans of agent SSH sources (system.read). */
export const sshBansQueryOptions = () =>
  queryOptions({
    queryKey: qk.sshBans,
    queryFn: ({ signal }) => api.call('get', '/api/v1/ssh-bans', { signal }),
  });

export const gatewayHostKeysQueryOptions = () =>
  queryOptions({
    queryKey: qk.gatewayHostKeys,
    queryFn: ({ signal }) => api.call('get', '/api/v1/system/gateway-host-keys', { signal }),
  });

export const statsOverviewQueryOptions = (range: StatsRange) =>
  queryOptions({
    queryKey: qk.statsOverview(range),
    queryFn: ({ signal }) => api.call('get', '/api/v1/stats/overview', { query: { range }, signal }),
  });

// ---- approvals: integrations, routes, deliveries, chat identities

export const integrationsQueryOptions = () =>
  queryOptions({
    queryKey: qk.integrations,
    queryFn: ({ signal }) => api.call('get', '/api/v1/integrations', { signal }),
  });

export const notificationRoutesQueryOptions = () =>
  queryOptions({
    queryKey: qk.notificationRoutes,
    queryFn: ({ signal }) => api.call('get', '/api/v1/notification-routes', { signal }),
  });

export const deliveriesQueryOptions = (state?: DeliveryState, limit = 100) =>
  queryOptions({
    queryKey: [...qk.deliveryList(state), limit],
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/notification-deliveries', {
        query: { limit, ...(state ? { state } : {}) },
        signal,
      }),
  });

export const myProviderLinksQueryOptions = () =>
  queryOptions({
    queryKey: qk.myProviderLinks,
    queryFn: ({ signal }) => api.call('get', '/api/v1/me/provider-links', { signal }),
  });

export const operatorProviderLinksQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.operatorProviderLinks(id),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/operators/{id}/provider-links', { path: { id }, signal }),
  });

// ---- destination-side audit (WP25): destination-reported, unverified

export const sessionDestinationRecordsQueryOptions = (sessionId: string) =>
  queryOptions({
    queryKey: qk.sessionDestinationRecords(sessionId),
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/access-sessions/{id}/destination-records', {
        path: { id: sessionId },
        signal,
      }),
  });

/** Full record incl. exe/argv/cwd (recording.play, audited per access). Untrusted text. */
export const destinationRecordQueryOptions = (id: string) =>
  queryOptions({
    queryKey: qk.destinationRecord(id),
    queryFn: ({ signal }) => api.call('get', '/api/v1/destination-records/{id}', { path: { id }, signal }),
    staleTime: Infinity,
  });

export const destinationCollectorsQueryOptions = (serverId?: string) =>
  queryOptions({
    queryKey: serverId ? qk.serverDestinationCollectors(serverId) : qk.destinationCollectors,
    queryFn: ({ signal }) =>
      api.call('get', '/api/v1/destination-collectors', {
        ...(serverId ? { query: { server_id: serverId } } : {}),
        signal,
      }),
  });
