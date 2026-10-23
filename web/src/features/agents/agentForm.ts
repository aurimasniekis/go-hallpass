import type { Agent, AgentCreate, AgentPatch } from '../../api/types';
import { labelsToTags } from '../../lib/labels';
import { cleanList, labelsFromTags, splitLines } from '../servers/formUtils';

/** Values of the agent create/edit form. Lists are tag inputs; labels are `key=value` tags. */
export interface AgentFormValues {
  name: string;
  description?: string;
  enabled?: boolean;
  source_cidrs?: string[];
  groups?: string[];
  labels?: string[];
  /** Create only: authorized_keys lines, one per line. */
  public_keys?: string;
}

export function toAgentCreate(v: AgentFormValues): AgentCreate {
  const keys = splitLines(v.public_keys);
  return {
    name: v.name.trim(),
    description: (v.description ?? '').trim(),
    enabled: v.enabled ?? true,
    source_cidrs: cleanList(v.source_cidrs),
    groups: cleanList(v.groups),
    labels: labelsFromTags(v.labels),
    ...(keys.length > 0 ? { public_keys: keys } : {}),
  };
}

export function toAgentPatch(v: AgentFormValues, version: number): AgentPatch {
  return {
    version,
    name: v.name.trim(),
    description: (v.description ?? '').trim(),
    source_cidrs: cleanList(v.source_cidrs),
    groups: cleanList(v.groups),
    labels: labelsFromTags(v.labels),
  };
}

export function agentFormValues(a: Agent): AgentFormValues {
  return {
    name: a.name,
    description: a.description,
    enabled: a.enabled,
    source_cidrs: a.source_cidrs ?? [],
    groups: a.groups ?? [],
    labels: labelsToTags(a.labels),
  };
}
