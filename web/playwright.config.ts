import { defineConfig, devices } from '@playwright/test';

// E2E runs against a real `hallpass serve` (UI embedded) or a Vite dev server proxying to one.
// When HALLPASS_E2E_URL is unset, every spec skips (see e2e/env.ts) so local `pnpm e2e` stays green
// without a backend.
const baseURL = process.env.HALLPASS_E2E_URL;

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    ...(baseURL ? { baseURL } : {}),
    trace: 'retain-on-failure',
    colorScheme: 'light',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
  ],
});
