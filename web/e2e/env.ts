import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { test } from '@playwright/test';

export const e2eUrl = process.env.HALLPASS_E2E_URL;

/** Skips the calling file's tests when no backend URL is configured. */
export function requireBackend(): void {
  test.skip(!e2eUrl, 'HALLPASS_E2E_URL is not set; E2E specs need a running hallpass backend.');
}

const here = dirname(fileURLToPath(import.meta.url));
/** Generated at test time and kept in web/.e2e-state (gitignored); never committed. */
export const STATE_DIR = join(here, '..', '.e2e-state');
export const STORAGE_STATE = join(STATE_DIR, 'storage.json');
const ADMIN_FILE = join(STATE_DIR, 'admin.json');

export interface AdminCredentials {
  email: string;
  password: string;
  totpSecret: string;
}

export function saveAdmin(admin: AdminCredentials): void {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(ADMIN_FILE, JSON.stringify(admin), { mode: 0o600 });
}

export function loadAdmin(): AdminCredentials | null {
  try {
    return JSON.parse(readFileSync(ADMIN_FILE, 'utf8')) as AdminCredentials;
  } catch {
    return null;
  }
}

/** Shared scratch values between specs (agent key paths, created resource IDs). */
export function stateFile(name: string): string {
  mkdirSync(STATE_DIR, { recursive: true });
  return join(STATE_DIR, name);
}
