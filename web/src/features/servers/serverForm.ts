import type { Server, ServerInput } from '../../api/types';
import { labelsToTags } from '../../lib/labels';
import { cleanList, labelsFromTags } from './formUtils';

export interface ServerFormValues {
  alias: string;
  display_name?: string;
  description?: string;
  environment?: string;
  address?: string;
  port?: number | null;
  enabled?: boolean;
  groups?: string[];
  labels?: string[];
  metadata?: string[];
}

/**
 * Builds a ServerInput. `includeAddress` is false when editing a server whose address is redacted for the
 * caller (HP-SRV-010): sending an empty address would be refused (and must never overwrite the real one).
 */
export function toServerInput(
  v: ServerFormValues,
  opts: { includeAddress: boolean; version?: number },
): ServerInput {
  const body: ServerInput = {
    alias: v.alias.trim(),
    display_name: (v.display_name ?? '').trim() || v.alias.trim(),
    description: (v.description ?? '').trim(),
    environment: (v.environment ?? '').trim(),
    enabled: v.enabled ?? true,
    groups: cleanList(v.groups),
    labels: labelsFromTags(v.labels),
    metadata: labelsFromTags(v.metadata),
  };
  if (opts.includeAddress) {
    body.address = (v.address ?? '').trim();
    body.port = v.port ?? 22;
  }
  if (opts.version !== undefined) {
    body.version = opts.version;
  }
  return body;
}

export function serverFormValues(s: Server): ServerFormValues {
  return {
    alias: s.alias,
    display_name: s.display_name,
    description: s.description ?? '',
    environment: s.environment ?? '',
    ...(s.address_redacted ? {} : { address: s.address ?? '', port: s.port ?? 22 }),
    enabled: s.enabled,
    groups: s.groups ?? [],
    labels: labelsToTags(s.labels),
    metadata: labelsToTags(s.metadata),
  };
}

/** `host:port` for display; never reveals anything when the API redacted it. */
export function serverAddress(s: Pick<Server, 'address' | 'port' | 'address_redacted'>): string | null {
  if (s.address_redacted || !s.address) {
    return null;
  }
  const host = s.address.includes(':') && !s.address.startsWith('[') ? `[${s.address}]` : s.address;
  return s.port ? `${host}:${String(s.port)}` : host;
}
