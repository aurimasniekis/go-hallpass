import { expect, test } from '@playwright/test';

import { expectNoSeriousViolations } from './axe';
import { requireBackend } from './env';

requireBackend();

for (const scheme of ['light', 'dark'] as const) {
  test(`login page renders and has no serious axe violations (${scheme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto('/login');
    await expect(page.getByRole('heading', { level: 1, name: /sign in/i })).toBeVisible();
    await expect(page.getByRole('textbox', { name: 'Email' })).toBeVisible();
    await expectNoSeriousViolations(page);
  });
}

test('unknown SSO error codes are shown generically and the login form stays usable', async ({ page }) => {
  await page.goto('/login?sso_error=forbidden');
  await expect(page.getByText(/Single sign-on was refused/)).toBeVisible();
  await expect(page.getByRole('textbox', { name: 'Email' })).toBeVisible();
});

test('protected pages redirect to /login with a return path', async ({ page }) => {
  await page.goto('/requests?state=pending');
  await expect(page).toHaveURL(/\/login\?next=/);
});
