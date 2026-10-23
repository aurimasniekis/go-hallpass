/**
 * Query key roots. Keys mirror API resources (docs/PLAN.md §14.4): list keys are
 * `[root, filters]`, detail keys `[singular, id]`. The SSE invalidation map (src/sse/invalidation.ts)
 * refers to these roots, so add new resources here first.
 */
export const qk = {
  me: ['me'] as const,
  authConfig: ['auth-config'] as const,
  requests: ['requests'] as const,
  request: (id: string) => ['request', id] as const,
  grants: ['grants'] as const,
  grant: (id: string) => ['grant', id] as const,
  accessSessions: ['access-sessions'] as const,
  accessSession: (id: string) => ['access-session', id] as const,
  activities: ['activities'] as const,
  agents: ['agents'] as const,
  agent: (id: string) => ['agent', id] as const,
  effectiveAccess: ['effective-access'] as const,
  servers: ['servers'] as const,
  server: (id: string) => ['server', id] as const,
  roles: ['roles'] as const,
  role: (id: string) => ['role', id] as const,
  groups: ['groups'] as const,
  policy: ['policy'] as const,
  operators: ['operators'] as const,
  operator: (id: string) => ['operator', id] as const,
  notificationDeliveries: ['notification-deliveries'] as const,
  auditEvents: ['audit-events'] as const,
  system: ['system'] as const,
  stats: ['stats'] as const,
};
