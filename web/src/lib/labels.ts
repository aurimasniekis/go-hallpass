/**
 * Label maps (`{env: "prod"}`) are edited as `key=value` tags. Keys and values are operator-provided
 * configuration (trusted), but are still rendered as plain text.
 */
export function labelsToTags(labels: Record<string, string> | null | undefined): string[] {
  return Object.entries(labels ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`);
}

export interface ParsedLabels {
  labels: Record<string, string>;
  invalid: string[];
}

/** Parses `key=value` tags. Entries without `=` or with an empty key are reported as invalid. */
export function tagsToLabels(tags: readonly string[]): ParsedLabels {
  const labels: Record<string, string> = {};
  const invalid: string[] = [];
  for (const raw of tags) {
    const tag = raw.trim();
    const eq = tag.indexOf('=');
    if (eq <= 0) {
      invalid.push(raw);
      continue;
    }
    labels[tag.slice(0, eq).trim()] = tag.slice(eq + 1).trim();
  }
  return { labels, invalid };
}
