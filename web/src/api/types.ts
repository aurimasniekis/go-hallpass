/**
 * API types, derived from the OpenAPI 3.1 contract (`api/openapi.yaml`) through the generated
 * `schema.gen.ts` (openapi-typescript; regenerate with `make api`). Do not hand-write resource shapes
 * here: add an alias to the generated schema instead, so drift fails the type check.
 */
import type { components } from './schema.gen';

type S = components['schemas'];

// auth and self
export type AuthConfig = S['AuthConfig'];
export type AuthProviderSummary = AuthConfig['providers'][number];
export type LoginRequest = S['LoginRequest'];
export type LoginResult = S['LoginResult'];
export type CodeRequest = S['CodeRequest'];
export type ReauthRequest = S['ReauthRequest'];
export type BootstrapRequest = S['BootstrapRequest'];
export type AcceptInvitationRequest = S['AcceptInvitationRequest'];
export type PasswordRequest = S['PasswordRequest'];
export type ChangePasswordRequest = S['ChangePasswordRequest'];
export type LogoutResult = S['LogoutResult'];
export type Me = S['Me'];
export type MeSession = Me['session'];
export type SessionMethod = MeSession['method'];
export type TOTPEnrollment = S['TOTPEnrollment'];
export type RecoveryCodes = S['RecoveryCodes'];
export type OneTimeToken = S['OneTimeToken'];
export type WebSession = S['WebSession'];
export type Identity = S['Identity'];
export type IdentityLink = S['IdentityLink'];

// operators
export type Operator = S['Operator'];
export type OperatorRole = Operator['roles'][number];
export type OperatorCreate = S['OperatorCreate'];
export type OperatorPatch = S['OperatorPatch'];
export type InvitationCreate = S['InvitationCreate'];

// inventory
export type Agent = S['Agent'];
export type AgentDetail = S['AgentDetail'];
export type AgentCreate = S['AgentCreate'];
export type AgentPatch = S['AgentPatch'];
export type AgentKey = S['AgentKey'];
export type Group = S['Group'];
export type Server = S['Server'];
export type ServerInput = S['ServerInput'];
export type Role = S['Role'];
export type GitRules = S['GitRules'];
export type RoleInput = S['RoleInput'];
export type HostIdentity = S['HostIdentity'];
export type HostCA = S['HostCA'];
export type LoginCredential = S['LoginCredential'];
export type UserCA = S['UserCA'];
export type GatewayHostKey = S['GatewayHostKey'];
export type SSHBan = S['SSHBan'];

// policy
export type PolicyRule = S['PolicyRule'];
export type ApproverRule = S['ApproverRule'];
export type EffectiveAccess = S['EffectiveAccess'];
export type AgentOwners = S['AgentOwners'];
export type SelfApprovalSetting = S['SelfApprovalSetting'];
export type EffectiveAccessItem = EffectiveAccess['items'][number];

// access
export type AccessRequest = S['AccessRequest'];
export type RequestState = AccessRequest['state'];
export type RequestPage = S['RequestPage'];
export type Decision = S['Decision'];
export type Grant = S['Grant'];
export type GrantState = Grant['state'];
export type GrantPage = S['GrantPage'];
export type AccessSession = S['AccessSession'];
export type AccessSessionState = AccessSession['state'];
export type AccessSessionPage = S['AccessSessionPage'];
export type TimelineEvent = S['TimelineEvent'];
export type TimelinePage = S['TimelinePage'];
export type Channel = S['Channel'];
export type Segment = S['Segment'];
export type RecordPage = S['RecordPage'];
export type RecordEntry = RecordPage['records'][number];
export type SessionExport = S['SessionExport'];
/** Destination-reported exec record (WP25): never verified by HallPass; exe/argv/cwd are untrusted text. */
export type DestinationRecord = S['DestinationRecord'];
export type DestinationCollector = S['DestinationCollector'];
export type DestinationCollectorInput = S['DestinationCollectorInput'];

// audit, SSO settings, system
export type AuditEvent = S['AuditEvent'];
export type AuditPage = S['AuditPage'];
export type AuditVerify = S['AuditVerify'];
export type OIDCProvider = S['OIDCProvider'];
export type OIDCProviderInput = S['OIDCProviderInput'];
export type OIDCMapping = S['OIDCMapping'];
export type OIDCTestResult = S['OIDCTestResult'];
export type AuthSettings = S['AuthSettings'];
export type SystemStatus = S['SystemStatus'];
export type StatsOverview = S['StatsOverview'];

// approvals: integrations, routes, deliveries, chat identities (WP16)
export type Integration = S['Integration'];
export type IntegrationInput = S['IntegrationInput'];
export type IntegrationProvider = Integration['provider'];
export type NotificationRoute = S['NotificationRoute'];
export type Delivery = S['Delivery'];
export type ProviderLink = S['ProviderLink'];

/**
 * RFC 9457 problem details as received from the network. Unlike `components['schemas']['Problem']`,
 * every field is optional: the body is untrusted and may be malformed or come from a proxy.
 */
export interface Problem {
  type?: string;
  title?: string;
  status?: number;
  code?: string;
  detail?: string;
  instance?: string;
  errors?: ProblemFieldError[];
}

/** One entry of the problem `errors[]` extension (`{field, message}` per the spec). */
export interface ProblemFieldError {
  field?: string;
  message?: string;
  /** Tolerated for robustness (RFC 9457 examples use JSON pointers); the spec uses `field`. */
  pointer?: string;
  detail?: string;
  code?: string;
}

/** Cursor page envelope used by list endpoints (`{items, next_cursor}`). */
export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

/**
 * Live event payload (docs/PLAN.md §8.3). The backend sends only `type`, `resource`, `resource_id`
 * and `at`; reasons, addresses and secrets never travel over SSE.
 */
export interface LiveEvent {
  type: string;
  resource: string;
  resource_id?: string;
  version?: number;
  at?: string;
}
