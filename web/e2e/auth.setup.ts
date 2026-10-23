import { randomBytes } from 'node:crypto';

import { expect, test as setup } from '@playwright/test';

import { e2eUrl, loadAdmin, saveAdmin, STORAGE_STATE } from './env';
import { freshTotp } from './totp';

/**
 * Signs in once for the whole run and saves the browser storage state.
 *
 * Fresh backend (`bootstrap_required`): needs HALLPASS_E2E_SETUP_TOKEN from `hallpass admin bootstrap`,
 * creates the first administrator through /setup, enrolls TOTP (secret read from the page, codes computed
 * with RFC 6238) and acknowledges the recovery codes. Existing backend: signs in with the credentials the
 * first run generated (web/.e2e-state/admin.json, gitignored).
 */
setup('sign in as administrator', async ({ page, request }) => {
  setup.skip(!e2eUrl, 'HALLPASS_E2E_URL is not set');
  const config = (await (await request.get('/api/v1/auth/config')).json()) as { bootstrap_required: boolean };

  if (config.bootstrap_required) {
    const token = process.env.HALLPASS_E2E_SETUP_TOKEN;
    setup.skip(!token, 'Fresh backend: set HALLPASS_E2E_SETUP_TOKEN from `hallpass admin bootstrap`.');
    const admin = {
      email: 'admin@example.test',
      password: `e2e-${randomBytes(18).toString('base64url')}`,
      totpSecret: '',
    };
    await page.goto(`/setup?token=${encodeURIComponent(token ?? '')}`);
    await expect(page).toHaveURL(/\/setup$/); // token removed from the address bar
    await page.getByRole('textbox', { name: 'Email' }).fill(admin.email);
    await page.getByLabel('Display name').fill('E2E Admin');
    await page.getByLabel('Password', { exact: true }).fill(admin.password);
    await page.getByLabel('Confirm password').fill(admin.password);
    await page.getByRole('button', { name: 'Create administrator' }).click();

    const secret = page.getByLabel('Secret', { exact: true });
    await expect(secret).toHaveValue(/^[A-Z2-7]+=*$/);
    admin.totpSecret = await secret.inputValue();
    saveAdmin(admin);
    await page.getByLabel('Code from your app').fill(await freshTotp(admin.totpSecret));
    await page.getByRole('button', { name: 'Confirm' }).click();
    const dialog = page.getByRole('dialog', { name: 'Recovery codes' });
    await expect(dialog.getByRole('list', { name: 'Recovery codes' }).getByRole('listitem')).not.toHaveCount(
      0,
    );
    await dialog.getByRole('checkbox', { name: 'I have stored this securely' }).check();
    await dialog.getByRole('button', { name: 'Done' }).click();
  } else {
    const admin = loadAdmin();
    setup.skip(admin === null, 'Backend already set up by another run without saved credentials.');
    if (!admin) {
      return;
    }
    await page.goto('/login');
    await page.getByRole('textbox', { name: 'Email' }).fill(admin.email);
    await page.getByLabel('Password', { exact: true }).fill(admin.password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.getByLabel('Authentication code').fill(await freshTotp(admin.totpSecret));
    await page.getByRole('button', { name: 'Verify' }).click();
  }
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  await page.context().storageState({ path: STORAGE_STATE });
});
