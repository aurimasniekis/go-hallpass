import type { OIDCProvider, OIDCProviderInput } from '../../api/types';

/**
 * OIDC provider form state ↔ API body (`OIDCProviderInput`). The client secret is write-only
 * (HP-OIDC-007): the form never receives it; an empty field keeps the stored secret, and removing it
 * must be explicit.
 */
export interface ProviderFormValues {
  slug: string;
  display_name: string;
  issuer: string;
  client_id: string;
  /** New secret; empty = keep the stored one (or none on create). */
  client_secret?: string;
  remove_secret?: boolean;
  scopes: string[];
  groups_claim?: string;
  provisioning: 'preprovisioned' | 'jit';
  jit_email_domains: string[];
  jit_tenants: string[];
  jit_hosted_domains: string[];
  jit_groups: string[];
  allow_private_network: boolean;
  allow_cross_origin_endpoints: boolean;
  ca_bundle_pem?: string;
  stepup_fallback: 'none' | 'local_totp';
  acr_values: string[];
  end_session_enabled: boolean;
  enabled: boolean;
}

export const DEFAULT_SCOPES = ['openid', 'email', 'profile'];

interface JitShape {
  email_domains?: string[] | null;
  tenants?: string[] | null;
  hosted_domains?: string[] | null;
  groups?: string[] | null;
}

function list(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}

export function providerToForm(p: OIDCProvider | undefined): ProviderFormValues {
  const jit = (p?.jit ?? {}) as JitShape;
  return {
    slug: p?.slug ?? '',
    display_name: p?.display_name ?? '',
    issuer: p?.issuer ?? '',
    client_id: p?.client_id ?? '',
    client_secret: '',
    remove_secret: false,
    scopes: p ? [...p.scopes] : [...DEFAULT_SCOPES],
    groups_claim: p?.groups_claim ?? '',
    provisioning: p?.provisioning ?? 'preprovisioned',
    jit_email_domains: list(jit.email_domains),
    jit_tenants: list(jit.tenants),
    jit_hosted_domains: list(jit.hosted_domains),
    jit_groups: list(jit.groups),
    allow_private_network: p?.allow_private_network ?? false,
    allow_cross_origin_endpoints: p?.allow_cross_origin_endpoints ?? false,
    ca_bundle_pem: p?.ca_bundle_pem ?? '',
    stepup_fallback: p?.stepup_fallback === 'local_totp' ? 'local_totp' : 'none',
    acr_values: list(p?.acr_values),
    end_session_enabled: p?.end_session_enabled ?? false,
    enabled: p?.enabled ?? false,
  };
}

/**
 * Builds the request body. `client_secret` is included only when a new value was typed, or as `""`
 * when removal was requested; otherwise it is omitted so the server keeps the stored secret.
 */
export function formToProviderInput(v: ProviderFormValues, version?: number): OIDCProviderInput {
  const body: OIDCProviderInput = {
    slug: v.slug.trim(),
    display_name: v.display_name.trim(),
    issuer: v.issuer.trim(),
    client_id: v.client_id.trim(),
    scopes: v.scopes,
    groups_claim: (v.groups_claim ?? '').trim(),
    provisioning: v.provisioning,
    // The spec types `jit` as a bare object (`Record<string, never>`); the server expects JITRules
    // (internal/oidc/provider.go). Reported as a spec gap.
    jit: {
      email_domains: v.jit_email_domains,
      tenants: v.jit_tenants,
      hosted_domains: v.jit_hosted_domains,
      groups: v.jit_groups,
    } as unknown as OIDCProviderInput['jit'],
    allow_private_network: v.allow_private_network,
    allow_cross_origin_endpoints: v.allow_cross_origin_endpoints,
    ca_bundle_pem: v.ca_bundle_pem ?? '',
    stepup_fallback: v.stepup_fallback,
    acr_values: v.acr_values,
    end_session_enabled: v.end_session_enabled,
    enabled: v.enabled,
  };
  if (version !== undefined) {
    body.version = version;
  }
  if (v.remove_secret) {
    body.client_secret = '';
  } else if (v.client_secret && v.client_secret !== '') {
    body.client_secret = v.client_secret;
  }
  return body;
}
