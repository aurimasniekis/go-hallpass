import { Tooltip } from 'antd';

import { StatusBadge } from '../../ds/StatusBadge';
import type { CommandProvenance } from './replay/track';

/**
 * Command provenance labels (HP-REC-006). Hallpass never claims a command was verified: the gateway can
 * only say what it was asked to run (`captured`), what a destination collector reported
 * (`destination-audit`, unverified) or what was derived from keystrokes/output (`inferred`).
 */
export const PROVENANCE: Record<CommandProvenance, { label: string; title: string }> = {
  captured: {
    label: 'Captured',
    title: 'The exec request as the gateway received it. It is not proof of what the destination executed.',
  },
  'destination-audit': {
    label: 'Destination-reported, unverified',
    title:
      'Reported by a collector on the destination host. Hallpass cannot verify it; a compromised host can lie.',
  },
  inferred: { label: 'Inferred', title: 'Derived from keystrokes or output; may be wrong.' },
};

export function ProvenanceBadge({ provenance }: { provenance: CommandProvenance }) {
  const p = PROVENANCE[provenance];
  return (
    <Tooltip title={p.title}>
      <span>
        <StatusBadge tone={provenance === 'captured' ? 'info' : 'warning'}>{p.label}</StatusBadge>
      </span>
    </Tooltip>
  );
}
