import type { Operator, OperatorRole } from '../../api/types';

/** Operator roles (PLAN §12.5). Order: most to least privileged. */
export const OPERATOR_ROLES: readonly { value: OperatorRole; label: string; description: string }[] = [
  { value: 'administrator', label: 'Administrator', description: 'Full configuration and security settings' },
  { value: 'approver', label: 'Approver', description: 'Decide requests within approver-rule scope' },
  { value: 'auditor', label: 'Auditor', description: 'Read audit, sessions and recordings' },
  { value: 'viewer', label: 'Viewer', description: 'Read-only overview' },
];

export function roleLabel(role: string): string {
  return OPERATOR_ROLES.find((r) => r.value === role)?.label ?? role;
}

/** Roles assigned manually (editable here). SSO-mapped roles are managed by the identity provider. */
export function manualRoles(op: Pick<Operator, 'roles' | 'role_assignments'>): string[] {
  if (!op.role_assignments) {
    // Older servers without assignments: treat every role as manual.
    return [...op.roles];
  }
  return unique(op.role_assignments.filter((a) => a.source === 'manual').map((a) => a.role));
}

/** SSO-mapped roles with the mapping reference (group value or provider) when present. */
export function ssoRoles(
  op: Pick<Operator, 'role_assignments'>,
): { role: string; ref: string | undefined }[] {
  return (op.role_assignments ?? [])
    .filter((a) => a.source === 'sso')
    .map((a) => ({ role: a.role, ref: a.source_ref }));
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

/**
 * Turns a server-relative one-time URL (`/invite/<token>`, `/reset/<token>`,
 * `/auth/oidc/<slug>/start?…`) into an absolute link for sharing. Absolute or missing URLs fall back to
 * the raw token so the operator can still hand it over.
 */
export function shareableLink(
  url: string | undefined,
  token: string,
  origin: string = window.location.origin,
): string {
  if (url?.startsWith('/') && !url.startsWith('//')) {
    return `${origin}${url}`;
  }
  return token;
}
