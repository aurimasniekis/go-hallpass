import { defineConfig, devices } from '@playwright/test';

// E2E runs against a real `hallpass serve` with the UI embedded (`go build -tags embedui`), so the UI and
// API share one origin (mutations require a same-origin Origin header). When HALLPASS_E2E_URL is unset,
// every spec skips (see e2e/env.ts) so local `pnpm e2e` stays green without a backend.
//
// A fresh backend also needs HALLPASS_E2E_SETUP_TOKEN (printed by `hallpass admin bootstrap`); the
// `setup` project creates the first administrator once and saves the signed-in storage state.
const baseURL = process.env.HALLPASS_E2E_URL;

export default defineConfig({
  testDir: './e2e',
  // Flows share one backend and build on each other; keep them ordered.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  timeout: 60_000,
  use: {
    ...(baseURL ? { baseURL } : {}),
    trace: 'retain-on-failure',
    colorScheme: 'light',
  },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    { name: 'chromium', use: { ...devices['Desktop Chrome'] }, dependencies: ['setup'] },
  ],
});
