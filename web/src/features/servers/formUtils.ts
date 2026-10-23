import { isApiError } from '../../api/errors';
import { tagsToLabels } from '../../lib/labels';

/**
 * Form helpers shared by the inventory pages (agents, servers, roles, credentials). Values come from
 * antd forms; bodies sent to the API contain only fields defined in api/openapi.yaml (the server rejects
 * unknown fields).
 */

/** One entry per non-empty line; `#` comment lines are ignored. */
export function splitLines(text: string | null | undefined): string[] {
  return (text ?? '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l !== '' && !l.startsWith('#'));
}

/** Trims every entry and drops empty and duplicate ones, keeping order. */
export function cleanList(values: readonly string[] | null | undefined): string[] {
  const out: string[] = [];
  for (const v of values ?? []) {
    const t = v.trim();
    if (t !== '' && !out.includes(t)) {
      out.push(t);
    }
  }
  return out;
}

export class LabelFormatError extends Error {
  constructor(readonly invalid: string[]) {
    super(`Labels must be key=value: ${invalid.join(', ')}`);
    this.name = 'LabelFormatError';
  }
}

/** `key=value` tags → label map; throws LabelFormatError for malformed entries. */
export function labelsFromTags(tags: readonly string[] | null | undefined): Record<string, string> {
  const { labels, invalid } = tagsToLabels(tags ?? []);
  if (invalid.length > 0) {
    throw new LabelFormatError(invalid);
  }
  return labels;
}

/** Friendly text for PATCH conflicts (stale `If-Match` version). */
export function conflictHint(error: unknown): string | null {
  if (isApiError(error) && (error.isConflict || error.status === 428)) {
    return 'This item changed since you opened it. Close the dialog, reload the page and apply your change again.';
  }
  return null;
}

/** Empty or missing text renders as an em dash. */
export function orDash(value: string | null | undefined): string {
  return value === null || value === undefined || value === '' ? '—' : value;
}
