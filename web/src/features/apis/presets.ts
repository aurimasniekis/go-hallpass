import type { APIRule } from '../../api/types';

export type CredentialType = 'bearer' | 'header' | 'basic' | 'google_service_account';

/** A profile template offered when creating an access profile. */
export interface ProfileTemplate {
  id: string;
  name: string;
  description: string;
  rules: APIRule[];
}

/** A well-known API: its hosts, the credential it takes and starting points for access profiles. */
export interface ApiPreset {
  id: string;
  name: string;
  alias: string;
  hosts: string[];
  credentialType: CredentialType;
  credentialHint: string;
  templates: ProfileTemplate[];
}

/** Endpoints that create credentials: denied in every template, because a minted token would outlive the grant. */
const GITHUB_CREDENTIAL_ENDPOINTS: APIRule = {
  effect: 'deny',
  paths: ['/user/keys', '/user/keys/**', '/user/gpg_keys/**', '/authorizations/**', '/repos/*/*/keys/**'],
};

export const API_PRESETS: ApiPreset[] = [
  {
    id: 'github',
    name: 'GitHub',
    alias: 'github',
    hosts: ['api.github.com', 'uploads.github.com'],
    credentialType: 'bearer',
    credentialHint:
      'A fine-grained personal access token (or GitHub App token) limited to the repositories and permissions this profile needs.',
    templates: [
      {
        id: 'read',
        name: 'Read only',
        description: 'REST reads and GraphQL queries (gh pr list, gh issue view, …).',
        rules: [
          { effect: 'allow', methods: ['GET', 'HEAD'] },
          { effect: 'allow', methods: ['POST'], paths: ['/graphql'], graphql: ['query'] },
          GITHUB_CREDENTIAL_ENDPOINTS,
        ],
      },
      {
        id: 'issues',
        name: 'Issues and pull requests',
        description: 'Reads, plus comments, labels and pull requests (GraphQL mutations included).',
        rules: [
          { effect: 'allow', methods: ['GET', 'HEAD'] },
          { effect: 'allow', methods: ['POST'], paths: ['/graphql'], graphql: ['query', 'mutation'] },
          {
            effect: 'allow',
            methods: ['POST', 'PATCH'],
            paths: ['/repos/*/*/issues/**', '/repos/*/*/pulls/**', '/repos/*/*/pulls'],
          },
          GITHUB_CREDENTIAL_ENDPOINTS,
        ],
      },
    ],
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    alias: 'cloudflare',
    hosts: ['api.cloudflare.com'],
    credentialType: 'bearer',
    credentialHint: 'An API token limited to the accounts, zones and permissions this profile needs.',
    templates: [
      {
        id: 'read',
        name: 'Read only',
        description: 'Every GET request.',
        rules: [
          { effect: 'allow', methods: ['GET', 'HEAD'] },
          { effect: 'deny', paths: ['/client/v4/user/tokens/**', '/client/v4/accounts/*/tokens/**'] },
        ],
      },
      {
        id: 'dns',
        name: 'DNS records',
        description: 'Reads, plus changes to DNS records of any zone the token covers.',
        rules: [
          { effect: 'allow', methods: ['GET', 'HEAD'] },
          {
            effect: 'allow',
            methods: ['POST', 'PUT', 'PATCH', 'DELETE'],
            paths: ['/client/v4/zones/*/dns_records', '/client/v4/zones/*/dns_records/**'],
          },
          { effect: 'deny', paths: ['/client/v4/user/tokens/**', '/client/v4/accounts/*/tokens/**'] },
        ],
      },
    ],
  },
  {
    id: 'google',
    name: 'Google Cloud',
    alias: 'gcp',
    hosts: ['*.googleapis.com'],
    credentialType: 'google_service_account',
    credentialHint:
      'A service account key (JSON) for a service account with only the IAM roles this profile needs. HallPass sends short-lived access tokens.',
    templates: [
      {
        id: 'read',
        name: 'Read only',
        description: 'GET requests; service account keys can never be created.',
        rules: [
          { effect: 'allow', methods: ['GET', 'HEAD'] },
          {
            effect: 'deny',
            paths: ['/v1/projects/*/serviceAccounts/*/keys', '/v1/projects/*/serviceAccounts/*/keys/**'],
          },
        ],
      },
      {
        id: 'all',
        name: 'All calls the service account allows',
        description: 'Every method; the service account’s IAM roles are the limit.',
        rules: [
          { effect: 'allow' },
          {
            effect: 'deny',
            paths: ['/v1/projects/*/serviceAccounts/*/keys', '/v1/projects/*/serviceAccounts/*/keys/**'],
          },
        ],
      },
    ],
  },
];

export const CUSTOM_PRESET: ApiPreset = {
  id: 'custom',
  name: 'Custom API',
  alias: '',
  hosts: [],
  credentialType: 'bearer',
  credentialHint: 'A token with the least permissions this profile needs.',
  templates: [
    {
      id: 'read',
      name: 'Read only',
      description: 'GET and HEAD requests.',
      rules: [{ effect: 'allow', methods: ['GET', 'HEAD'] }],
    },
    { id: 'all', name: 'Everything', description: 'Every method and path.', rules: [{ effect: 'allow' }] },
  ],
};

/** The preset whose hosts a target uses, if any. */
export function presetForHosts(hosts: readonly string[] | undefined): ApiPreset | undefined {
  const first = hosts?.[0];
  return first ? API_PRESETS.find((p) => p.hosts.includes(first)) : undefined;
}
