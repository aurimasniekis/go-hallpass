/**
 * Sidebar navigation: every top-level page from docs/PLAN.md §14.3. Detail routes
 * (`/requests/$id`, `/roles/$id`, …) are reached from their lists and are not listed here.
 */
export interface NavItem {
  to: string;
  label: string;
  /** Permission(s) from `GET /me` needed to see the page (any of them). Cosmetic: the API enforces. */
  permission?: string | readonly string[];
}

export interface NavSection {
  label: string;
  items: readonly NavItem[];
}

export const NAV_SECTIONS: readonly NavSection[] = [
  { label: 'Overview', items: [{ to: '/', label: 'Dashboard', permission: 'dashboard.view' }] },
  {
    label: 'Access',
    items: [
      { to: '/requests', label: 'Requests', permission: 'requests.read' },
      { to: '/sessions', label: 'Sessions', permission: ['sessions.read', 'requests.read'] },
      { to: '/activities', label: 'Activities', permission: 'sessions.read' },
    ],
  },
  {
    label: 'Inventory',
    items: [
      { to: '/agents', label: 'Agents', permission: 'inventory.read' },
      { to: '/servers', label: 'Servers', permission: 'inventory.read' },
      { to: '/git', label: 'Git', permission: 'inventory.read' },
      { to: '/groups', label: 'Groups', permission: 'inventory.read' },
    ],
  },
  {
    label: 'Governance',
    items: [
      { to: '/policy', label: 'Policy', permission: 'policy.read' },
      { to: '/audit', label: 'Audit log', permission: 'audit.read' },
    ],
  },
  {
    label: 'Administration',
    items: [
      { to: '/operators', label: 'Operators', permission: 'operators.manage' },
      { to: '/settings/auth', label: 'Authentication', permission: 'auth.settings' },
      { to: '/settings/integrations', label: 'Integrations', permission: 'integrations.manage' },
      { to: '/settings/api-tokens', label: 'API tokens', permission: 'operators.manage' },
      { to: '/settings/storage', label: 'Storage & keys', permission: ['system.read', 'retention.manage'] },
      { to: '/settings/system', label: 'System', permission: 'dashboard.view' },
    ],
  },
  { label: 'Account', items: [{ to: '/me', label: 'My account' }] },
];

/** Sections with only the items `permissions` allow; empty sections are dropped. */
export function visibleNavSections(permissions: readonly string[] | undefined): NavSection[] {
  const granted = new Set(permissions ?? []);
  return NAV_SECTIONS.map((section) => ({
    ...section,
    items: section.items.filter((item) => {
      if (item.permission === undefined) {
        return true;
      }
      const needed = typeof item.permission === 'string' ? [item.permission] : item.permission;
      return needed.some((p) => granted.has(p));
    }),
  })).filter((section) => section.items.length > 0);
}

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
