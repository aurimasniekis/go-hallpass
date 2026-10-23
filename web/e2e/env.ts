import { test } from '@playwright/test';

export const e2eUrl = process.env.HALLPASS_E2E_URL;

/** Skips the calling file's tests when no backend URL is configured. */
export function requireBackend(): void {
  test.skip(!e2eUrl, 'HALLPASS_E2E_URL is not set; E2E specs need a running hallpass backend.');
}
