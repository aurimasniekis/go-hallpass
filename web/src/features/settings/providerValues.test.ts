import { describe, expect, it } from 'vitest';

import type { OIDCProvider } from '../../api/types';
import { DEFAULT_SCOPES, formToProviderInput, providerToForm } from './providerValues';

const provider: OIDCProvider = {
  id: 'oidc_1',
  slug: 'corp',
  display_name: 'Corp',
  issuer: 'https://idp.example.test',
  client_id: 'hallpass',
  has_client_secret: true,
  scopes: ['openid', 'email'],
  groups_claim: 'groups',
  provisioning: 'jit',
  jit: { email_domains: ['example.test'], groups: ['ops'] } as unknown as OIDCProvider['jit'],
  stepup_fallback: 'local_totp',
  acr_values: null,
  enabled: true,
  version: 4,
};

describe('provider form mapping', () => {
  it('never pre-fills the client secret and keeps it when the field stays empty', () => {
    const form = providerToForm(provider);
    expect(form.client_secret).toBe('');
    const body = formToProviderInput(form, 4);
    expect('client_secret' in body).toBe(false);
    expect(body.version).toBe(4);
    expect(body.jit).toEqual({
      email_domains: ['example.test'],
      tenants: [],
      hosted_domains: [],
      groups: ['ops'],
    });
    expect(body.stepup_fallback).toBe('local_totp');
  });

  it('sends a new secret only when typed, and an empty string only for explicit removal', () => {
    const form = providerToForm(provider);
    expect(formToProviderInput({ ...form, client_secret: 's3cret' }).client_secret).toBe('s3cret');
    expect(formToProviderInput({ ...form, client_secret: 's3cret', remove_secret: true }).client_secret).toBe(
      '',
    );
  });

  it('defaults new providers to standard scopes, pre-provisioning and disabled', () => {
    const form = providerToForm(undefined);
    expect(form.scopes).toEqual(DEFAULT_SCOPES);
    expect(form.provisioning).toBe('preprovisioned');
    expect(form.enabled).toBe(false);
    expect(form.stepup_fallback).toBe('none');
  });
});
