import type { RequestState } from '../../api/types';

/** URL search params of `/requests` (HP-UI-008: filters live in the URL and can be saved). */
export interface RequestSearch {
  state?: RequestState;
  agent_id?: string;
  server_id?: string;
}

export const REQUEST_STATES: readonly RequestState[] = [
  'pending',
  'approved',
  'denied',
  'expired',
  'canceled',
];

const ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

function id(value: unknown): string | undefined {
  return typeof value === 'string' && ID_RE.test(value) ? value : undefined;
}

/** Accepts only known states and ID-shaped strings; anything else is dropped (never sent to the API). */
export function validateRequestSearch(search: Record<string, unknown>): RequestSearch {
  const out: RequestSearch = {};
  if (typeof search.state === 'string' && (REQUEST_STATES as readonly string[]).includes(search.state)) {
    out.state = search.state as RequestState;
  }
  const agent = id(search.agent_id);
  if (agent) {
    out.agent_id = agent;
  }
  const server = id(search.server_id);
  if (server) {
    out.server_id = server;
  }
  return out;
}

/** Saved-filter values → search (re-validated, since localStorage is untrusted input). */
export function searchFromSaved(filters: Record<string, string>): RequestSearch {
  return validateRequestSearch(filters);
}

export function searchToFilters(search: RequestSearch): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(search)) {
    if (typeof v === 'string' && v !== '') {
      out[k] = v;
    }
  }
  return out;
}
