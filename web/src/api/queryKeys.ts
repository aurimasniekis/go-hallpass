/**
 * Query key roots. Keys mirror API resources (docs/PLAN.md §14.4): list keys are
 * `[root, filters]`, detail keys `[singular, id]`, and sub-resources hang below their parent's detail
 * key so invalidating `['access-session', id]` also refreshes its channels, segments and timeline.
 * The SSE invalidation map (src/sse/invalidation.ts) refers to these roots, so add new resources here first.
 */
export const qk = {
  me: ['me'] as const,
  mySessions: ['me-sessions'] as const,
  myIdentities: ['me-identities'] as const,
  authConfig: ['auth-config'] as const,

  requests: ['requests'] as const,
  requestList: (filters: object) => ['requests', filters] as const,
  request: (id: string) => ['request', id] as const,

  grants: ['grants'] as const,
  grantList: (filters: object) => ['grants', filters] as const,
  grant: (id: string) => ['grant', id] as const,

  accessSessions: ['access-sessions'] as const,
  accessSessionList: (filters: object) => ['access-sessions', filters] as const,
  accessSessionRoot: ['access-session'] as const,
  accessSession: (id: string) => ['access-session', id] as const,
  sessionChannels: (id: string) => ['access-session', id, 'channels'] as const,
  sessionSegments: (id: string) => ['access-session', id, 'segments'] as const,
  sessionTimeline: (id: string) => ['access-session', id, 'timeline'] as const,
  sessionDestinationRecords: (id: string) => ['access-session', id, 'destination-records'] as const,
  destinationRecord: (id: string) => ['destination-record', id] as const,
  destinationCollectors: ['destination-collectors'] as const,
  serverDestinationCollectors: (serverId: string) =>
    ['destination-collectors', { server: serverId }] as const,
  /** Decrypted record pages. Not invalidated by live events: finalized pages never change. */
  recordingPage: (segmentId: string, fromSeq: number) => ['recording', segmentId, fromSeq] as const,

  activities: ['activities'] as const,
  activityList: (endedSince: number | undefined) => ['activities', { ended_since: endedSince ?? 0 }] as const,

  sshBans: ['system', 'ssh-bans'] as const,

  agents: ['agents'] as const,
  agent: (id: string) => ['agent', id] as const,
  effectiveAccess: ['effective-access'] as const,
  agentEffectiveAccess: (id: string) => ['effective-access', 'agent', id] as const,
  serverEffectiveAccess: (id: string) => ['effective-access', 'server', id] as const,

  groups: ['groups'] as const,
  groupList: (kind: string | undefined) => ['groups', kind ?? 'all'] as const,

  servers: ['servers'] as const,
  server: (id: string) => ['server', id] as const,
  hostIdentities: (serverId: string) => ['server', serverId, 'host-identities'] as const,
  roles: ['roles'] as const,
  serverRoles: (serverId: string) => ['roles', { server: serverId }] as const,
  role: (id: string) => ['role', id] as const,
  credentials: (roleId: string) => ['role', roleId, 'credentials'] as const,
  userCAs: ['user-cas'] as const,

  policy: ['policy'] as const,
  policyRules: ['policy', 'rules'] as const,
  approverRules: ['policy', 'approver-rules'] as const,
  policyVersion: ['policy', 'version'] as const,
  // Owners and the self-approval prohibition are policy state (changing either bumps the policy version and
  // emits a `policy` live event), so they hang below the policy root rather than the agent detail key.
  selfApproval: ['policy', 'self-approval'] as const,
  agentOwners: (agentId: string) => ['policy', 'agent-owners', agentId] as const,

  operators: ['operators'] as const,
  operator: (id: string) => ['operator', id] as const,
  operatorSessions: (id: string) => ['operator', id, 'sessions'] as const,
  operatorIdentities: (id: string) => ['operator', id, 'identities'] as const,

  integrations: ['integrations'] as const,
  integration: (id: string) => ['integration', id] as const,
  notificationRoutes: ['notification-routes'] as const,
  notificationDeliveries: ['notification-deliveries'] as const,
  deliveryList: (state: string | undefined) => ['notification-deliveries', state ?? 'all'] as const,
  myProviderLinks: ['me-provider-links'] as const,
  operatorProviderLinks: (id: string) => ['operator', id, 'provider-links'] as const,

  auditEvents: ['audit-events'] as const,
  auditList: (filters: object) => ['audit-events', filters] as const,
  auditVerify: ['audit-verify'] as const,

  oidcProviders: ['oidc-providers'] as const,
  oidcProvider: (id: string) => ['oidc-provider', id] as const,
  oidcMappings: (id: string) => ['oidc-provider', id, 'mappings'] as const,
  oidcTestLogin: (id: string) => ['oidc-provider', id, 'test-login'] as const,
  authSettings: ['auth-settings'] as const,

  system: ['system'] as const,
  systemStatus: ['system', 'status'] as const,
  gatewayHostKeys: ['system', 'gateway-host-keys'] as const,

  stats: ['stats'] as const,
  statsOverview: (range: string) => ['stats', 'overview', range] as const,
};
