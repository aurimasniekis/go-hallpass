import { describe, expect, it } from 'vitest';

import { activeNavPath, NAV_PATHS } from './nav';

/** Top-level (non-detail) routes from docs/PLAN.md §14.3, excluding /login and /setup. */
const PLAN_LIST_ROUTES = [
  '/',
  '/requests',
  '/sessions',
  '/activities',
  '/agents',
  '/servers',
  '/groups',
  '/policy',
  '/operators',
  '/settings/auth',
  '/settings/integrations',
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
    expect(activeNavPath('/nope')).toBeUndefined();
  });
});
