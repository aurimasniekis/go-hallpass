/**
 * Sidebar navigation: every top-level page from docs/PLAN.md §14.3. Detail routes
 * (`/requests/$id`, `/roles/$id`, …) are reached from their lists and are not listed here.
 */
export interface NavItem {
  to: string;
  label: string;
}

export interface NavSection {
  label: string;
  items: readonly NavItem[];
}

export const NAV_SECTIONS: readonly NavSection[] = [
  { label: 'Overview', items: [{ to: '/', label: 'Dashboard' }] },
  {
    label: 'Access',
    items: [
      { to: '/requests', label: 'Requests' },
      { to: '/sessions', label: 'Sessions' },
      { to: '/activities', label: 'Activities' },
    ],
  },
  {
    label: 'Inventory',
    items: [
      { to: '/agents', label: 'Agents' },
      { to: '/servers', label: 'Servers' },
      { to: '/groups', label: 'Groups' },
    ],
  },
  {
    label: 'Governance',
    items: [
      { to: '/policy', label: 'Policy' },
      { to: '/audit', label: 'Audit log' },
    ],
  },
  {
    label: 'Administration',
    items: [
      { to: '/operators', label: 'Operators' },
      { to: '/settings/auth', label: 'Authentication' },
      { to: '/settings/integrations', label: 'Integrations' },
      { to: '/settings/storage', label: 'Storage & keys' },
      { to: '/settings/system', label: 'System' },
    ],
  },
  { label: 'Account', items: [{ to: '/me', label: 'My account' }] },
];

export const NAV_PATHS: readonly string[] = NAV_SECTIONS.flatMap((s) => s.items.map((i) => i.to));

/** Nav entry to highlight for a pathname: longest matching prefix (so `/requests/r1` selects Requests). */
export function activeNavPath(pathname: string): string | undefined {
  let best: string | undefined;
  for (const path of NAV_PATHS) {
    const matches = path === '/' ? pathname === '/' : pathname === path || pathname.startsWith(`${path}/`);
    if (matches && (best === undefined || path.length > best.length)) {
      best = path;
    }
  }
  if (best === undefined && pathname.startsWith('/roles/')) {
    return '/servers';
  }
  return best;
}
