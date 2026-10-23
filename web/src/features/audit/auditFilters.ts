/**
 * Audit list filters (URL search params, HP-UI-008). Values are bounded and trimmed; anything else in
 * the URL is dropped so a crafted link cannot smuggle parameters into API calls.
 */
export interface AuditSearch {
  action?: string;
  actor_id?: string;
  target_id?: string;
}

const FIELDS = ['action', 'actor_id', 'target_id'] as const;
const SAFE = /^[A-Za-z0-9_.:-]{1,128}$/;

export function parseAuditSearch(search: Record<string, unknown>): AuditSearch {
  const out: AuditSearch = {};
  for (const f of FIELDS) {
    const v = search[f];
    if (typeof v === 'string' && SAFE.test(v.trim())) {
      out[f] = v.trim();
    }
  }
  return out;
}

/** Search params as plain strings (for saved filters). */
export function auditSearchToValues(search: AuditSearch): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of FIELDS) {
    const v = search[f];
    if (v) {
      out[f] = v;
    }
  }
  return out;
}

/** Pretty JSON for display inside <pre>; never parsed as HTML. */
export function formatDetails(details: unknown): string {
  try {
    return JSON.stringify(details ?? {}, null, 2);
  } catch {
    return String(details);
  }
}
