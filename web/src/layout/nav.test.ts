import { describe, expect, it } from 'vitest';

import { activeNavPath, NAV_PATHS, visibleNavSections } from './nav';

/** Top-level (non-detail) routes from docs/PLAN.md §14.3, excluding /login and /setup. */
const PLAN_LIST_ROUTES = [
  '/',
  '/requests',
  '/sessions',
  '/activities',
  '/agents',
  '/servers',
  '/git',
  '/groups',
  '/policy',
  '/operators',
  '/settings/auth',
  '/settings/integrations',
  '/settings/api-tokens',
  '/settings/storage',
  '/settings/system',
  '/audit',
  '/me',
];

describe('navigation', () => {
  it('lists every top-level page from PLAN §14.3', () => {
    expect([...NAV_PATHS].sort()).toEqual([...PLAN_LIST_ROUTES].sort());
  });

  it('highlights the closest section for detail routes', () => {
    expect(activeNavPath('/')).toBe('/');
    expect(activeNavPath('/requests/r1')).toBe('/requests');
    expect(activeNavPath('/settings/auth')).toBe('/settings/auth');
    expect(activeNavPath('/roles/x')).toBe('/servers');
    expect(activeNavPath('/git/srv_1')).toBe('/git');
    expect(activeNavPath('/nope')).toBeUndefined();
  });

  it('shows only pages the operator may open (cosmetic gating)', () => {
    const paths = (perms: string[]) => visibleNavSections(perms).flatMap((s) => s.items.map((i) => i.to));
    expect(paths([])).toEqual(['/me']);
    const viewer = paths(['dashboard.view', 'requests.read', 'sessions.read', 'inventory.read']);
    expect(viewer).toContain('/requests');
    expect(viewer).toContain('/agents');
    expect(viewer).not.toContain('/operators');
    expect(viewer).not.toContain('/settings/auth');
    expect(paths(['operators.manage'])).toEqual(['/operators', '/settings/api-tokens', '/me']);
    // Sections without visible items are dropped entirely.
    expect(visibleNavSections(['audit.read']).map((s) => s.label)).toEqual(['Governance', 'Account']);
  });
});
