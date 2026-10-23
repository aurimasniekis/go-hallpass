import type { Me, Operator } from '../api/types';

/**
 * Test fixtures shaped by the generated OpenAPI types. They hold no secrets: tokens are obviously fake
 * placeholders and every test creates its own values.
 */

export function makeOperator(overrides: Partial<Operator> = {}): Operator {
  return {
    id: 'op_1',
    email: 'ada@example.test',
    display_name: 'Ada',
    enabled: true,
    provisioned_via: 'local',
    roles: ['administrator'],
    role_assignments: [{ role: 'administrator', source: 'manual' }],
    groups: [],
    has_password: true,
    mfa_enrolled: true,
    mfa_required: true,
    version: 1,
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  };
}

export function makeMe(
  overrides: {
    csrf?: string;
    permissions?: string[];
    operator?: Partial<Operator>;
    session?: Partial<Me['session']>;
  } = {},
): Me {
  return {
    operator: makeOperator(overrides.operator),
    permissions: overrides.permissions ?? ['dashboard.view'],
    csrf_token: overrides.csrf ?? 'csrf-test',
    session: {
      id: 'ws_1',
      method: 'password',
      auth_at: '2026-01-01T00:00:00Z',
      mfa_at: '2026-01-01T00:00:00Z',
      expires_at: '2026-01-02T00:00:00Z',
      limited: false,
      needs_enroll: false,
      ...overrides.session,
    },
  };
}

export function jsonResponse(status: number, body: unknown, contentType = 'application/json'): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': contentType } });
}

export function problemResponse(status: number, code: string, detail = code): Response {
  return jsonResponse(
    status,
    { type: 'about:blank', title: code, status, code, detail },
    'application/problem+json',
  );
}
