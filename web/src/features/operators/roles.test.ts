import { describe, expect, it } from 'vitest';

import { manualRoles, roleLabel, shareableLink, ssoRoles } from './roles';

describe('operator roles', () => {
  it('separates manual and SSO-mapped roles', () => {
    const op = {
      roles: ['administrator', 'approver'] as ('administrator' | 'approver')[],
      role_assignments: [
        { role: 'approver', source: 'manual' as const },
        { role: 'administrator', source: 'sso' as const, source_ref: 'hp-admins' },
        { role: 'approver', source: 'manual' as const },
      ],
    };
    expect(manualRoles(op)).toEqual(['approver']);
    expect(ssoRoles(op)).toEqual([{ role: 'administrator', ref: 'hp-admins' }]);
  });

  it('treats roles as manual when assignments are absent', () => {
    expect(manualRoles({ roles: ['viewer'], role_assignments: null })).toEqual(['viewer']);
    expect(ssoRoles({ role_assignments: null })).toEqual([]);
  });

  it('labels known roles and passes unknown ones through', () => {
    expect(roleLabel('auditor')).toBe('Auditor');
    expect(roleLabel('custom')).toBe('custom');
  });
});

describe('shareableLink', () => {
  it('makes server-relative URLs absolute and falls back to the token', () => {
    expect(shareableLink('/invite/abc', 'abc', 'https://hp.example.test')).toBe(
      'https://hp.example.test/invite/abc',
    );
    expect(shareableLink(undefined, 'abc', 'https://hp.example.test')).toBe('abc');
    expect(shareableLink('//evil.example/x', 'abc', 'https://hp.example.test')).toBe('abc');
    expect(shareableLink('https://elsewhere.example/x', 'abc', 'https://hp.example.test')).toBe('abc');
  });
});
