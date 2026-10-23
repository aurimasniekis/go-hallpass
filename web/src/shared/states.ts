import type { StatusTone } from '../ds/StatusBadge';

/**
 * Display mapping for server-side lifecycle states. Unknown states (additive API changes) fall back to
 * a neutral badge showing the raw state, so nothing is hidden or mislabeled.
 */
export interface StateDisplay {
  tone: StatusTone;
  label: string;
}

type StateMap = Record<string, StateDisplay>;

const REQUEST: StateMap = {
  pending: { tone: 'processing', label: 'Pending' },
  approved: { tone: 'success', label: 'Approved' },
  denied: { tone: 'error', label: 'Denied' },
  expired: { tone: 'neutral', label: 'Expired' },
  canceled: { tone: 'neutral', label: 'Canceled' },
};

const GRANT: StateMap = {
  active: { tone: 'success', label: 'Active' },
  expired: { tone: 'neutral', label: 'Expired' },
  revoked: { tone: 'error', label: 'Revoked' },
};

const SESSION: StateMap = {
  open: { tone: 'success', label: 'Open' },
  closing: { tone: 'warning', label: 'Closing' },
  closed: { tone: 'neutral', label: 'Closed' },
};

const CHANNEL: StateMap = {
  opening: { tone: 'processing', label: 'Opening' },
  active: { tone: 'success', label: 'Live' },
  closed: { tone: 'neutral', label: 'Closed' },
  failed: { tone: 'error', label: 'Failed' },
  interrupted: { tone: 'warning', label: 'Interrupted' },
};

const CREDENTIAL: StateMap = {
  pending: { tone: 'warning', label: 'Pending' },
  active: { tone: 'success', label: 'Active' },
  retiring: { tone: 'warning', label: 'Retiring' },
  retired: { tone: 'neutral', label: 'Retired' },
  revoked: { tone: 'error', label: 'Revoked' },
};

const HOST_IDENTITY: StateMap = {
  pending: { tone: 'warning', label: 'Pending confirmation' },
  active: { tone: 'success', label: 'Active' },
  retired: { tone: 'neutral', label: 'Retired' },
};

const SEGMENT: StateMap = {
  open: { tone: 'processing', label: 'Recording' },
  finalized: { tone: 'success', label: 'Finalized' },
  interrupted: { tone: 'warning', label: 'Interrupted' },
  missing: { tone: 'error', label: 'Missing' },
  failed: { tone: 'error', label: 'Failed' },
  deleted: { tone: 'neutral', label: 'Deleted' },
};

const GENERIC: StateMap = {
  active: { tone: 'success', label: 'Active' },
  enabled: { tone: 'success', label: 'Enabled' },
  disabled: { tone: 'neutral', label: 'Disabled' },
  revoked: { tone: 'error', label: 'Revoked' },
  retired: { tone: 'neutral', label: 'Retired' },
};

export const STATE_MAPS = {
  request: REQUEST,
  grant: GRANT,
  session: SESSION,
  channel: CHANNEL,
  credential: CREDENTIAL,
  hostIdentity: HOST_IDENTITY,
  segment: SEGMENT,
  generic: GENERIC,
} as const;

export type StateKind = keyof typeof STATE_MAPS;

export function stateDisplay(kind: StateKind, state: string | null | undefined): StateDisplay {
  if (!state) {
    return { tone: 'neutral', label: 'Unknown' };
  }
  return STATE_MAPS[kind][state] ?? { tone: 'neutral', label: state };
}
