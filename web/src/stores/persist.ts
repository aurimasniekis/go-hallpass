/**
 * localStorage access that never throws: storage can be disabled (privacy modes, sandboxed frames,
 * quota errors). Only non-sensitive UI preferences are persisted. Never store tokens or server data here.
 */
export function readPersisted(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writePersisted(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Preference simply is not persisted.
  }
}
