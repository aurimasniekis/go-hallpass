import { StatusBadge } from '../ds/StatusBadge';
import { stateDisplay, type StateKind } from './states';

/** Lifecycle state of a resource, with label text (never color alone). */
export function StateBadge({ kind, state }: { kind: StateKind; state: string | null | undefined }) {
  const { tone, label } = stateDisplay(kind, state);
  return <StatusBadge tone={tone}>{label}</StatusBadge>;
}
