/**
 * URL search params of `/sessions` (HP-UI-008: filters live in the URL so views can be shared and saved).
 * Everything else in the query string is dropped.
 */
export type SessionsTab = 'sessions' | 'grants';

export const SESSION_STATES = ['open', 'closing', 'closed'] as const;
export const GRANT_STATES = ['active', 'expired', 'revoked'] as const;
export type SessionStateFilter = (typeof SESSION_STATES)[number];
export type GrantStateFilter = (typeof GRANT_STATES)[number];

export interface SessionsSearch {
  tab?: SessionsTab;
  state?: string;
  agent_id?: string;
  server_id?: string;
}

const ID = /^[A-Za-z0-9_.:-]{1,64}$/;

export function validateSessionsSearch(search: Record<string, unknown>): SessionsSearch {
  const tab: SessionsTab = search.tab === 'grants' ? 'grants' : 'sessions';
  const states: readonly string[] = tab === 'grants' ? GRANT_STATES : SESSION_STATES;
  const out: SessionsSearch = {};
  if (tab === 'grants') {
    out.tab = 'grants';
  }
  if (typeof search.state === 'string' && states.includes(search.state)) {
    out.state = search.state;
  }
  for (const key of ['agent_id', 'server_id'] as const) {
    const v = search[key];
    if (typeof v === 'string' && ID.test(v)) {
      out[key] = v;
    }
  }
  return out;
}
