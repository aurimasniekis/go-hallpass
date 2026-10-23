import type { LoginCredential } from '../../api/types';

/** Probe results older than this no longer allow a normal activation (internal/credentials ProbeFreshness). */
export const PROBE_FRESHNESS_MS = 24 * 3600 * 1000;

export interface CredentialActions {
  probe: boolean;
  /** Normal activation: pending with a fresh successful probe. */
  activate: boolean;
  /** Forced activation is offered only after the latest probe failed (or a fresh success is missing). */
  forceActivate: boolean;
  revoke: boolean;
}

/** Which lifecycle actions make sense for a credential (PLAN §11.3, §18.4, §18.11). The server decides. */
export function credentialActions(
  c: Pick<LoginCredential, 'state' | 'probe_ok_at' | 'probe_error'>,
  nowMs: number,
): CredentialActions {
  const live = c.state === 'pending' || c.state === 'active' || c.state === 'retiring';
  const okAt = c.probe_ok_at ? Date.parse(c.probe_ok_at) : Number.NaN;
  const fresh = Number.isFinite(okAt) && nowMs - okAt < PROBE_FRESHNESS_MS && !c.probe_error;
  const pending = c.state === 'pending';
  return {
    probe: live,
    activate: pending && fresh,
    forceActivate: pending && !fresh && Boolean(c.probe_error),
    revoke: live,
  };
}

/** Next step for the operator, following the rotation procedure (generate → install → probe → activate). */
export function credentialNextStep(
  c: Pick<LoginCredential, 'state' | 'probe_ok_at' | 'probe_error'>,
  nowMs: number,
): string | null {
  if (c.state !== 'pending') {
    return null;
  }
  const a = credentialActions(c, nowMs);
  if (a.activate) {
    return 'Probe succeeded. Activate to start using this key; the previous key keeps working during the overlap window.';
  }
  if (c.probe_error) {
    return 'The last probe failed. Check that the authorized_keys line is installed for the remote user, then probe again.';
  }
  return 'Install the authorized_keys line on the destination, then run a probe.';
}
