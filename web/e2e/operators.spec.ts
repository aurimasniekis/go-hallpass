import { randomBytes } from 'node:crypto';

import { expect, test, type Page } from '@playwright/test';

import { Api } from './api';
import { e2eUrl, requireBackend, STORAGE_STATE } from './env';
import { throttle, trackApiRequests } from './throttle';
import { freshTotp } from './totp';

requireBackend();
test.use({ storageState: STORAGE_STATE });
test.describe.configure({ mode: 'serial' });

/**
 * Finishes a sign-in after the password step: enrolls TOTP when the account has none yet (secret read from the
 * page, recovery codes acknowledged), then verifies a fresh code. Returns the TOTP secret.
 */
async function completeMfa(page: Page, knownSecret = ''): Promise<string> {
  const secretField = page.getByLabel('Secret', { exact: true });
  const codeField = page.getByLabel('Authentication code');
  await expect(secretField.or(codeField)).toBeVisible();
  let secret = knownSecret;
  if (await secretField.isVisible()) {
    await expect(secretField).toHaveValue(/^[A-Z2-7]+=*$/);
    secret = await secretField.inputValue();
    await page.getByLabel('Code from your app').fill(await freshTotp(secret));
    await page.getByRole('button', { name: 'Confirm' }).click();
    const dialog = page.getByRole('dialog', { name: 'Recovery codes' });
    await dialog.getByRole('checkbox', { name: 'I have stored this securely' }).check();
    await dialog.getByRole('button', { name: 'Done' }).click();
  }
  await codeField.fill(await freshTotp(secret));
  await page.getByRole('button', { name: 'Verify' }).click();
  return secret;
}

/**
 * Operator onboarding by invitation: an administrator invites an approver, the invitee accepts the single-use link
 * in a separate browser, chooses a password, enrolls TOTP and signs in with the invited role; the link cannot be
 * used twice.
 */
test('invite an operator who accepts, enrolls TOTP and signs in', async ({ page, browser }) => {
  test.setTimeout(180_000);
  trackApiRequests(page);
  await throttle(150);
  const email = `invitee-${Date.now().toString(36)}@example.test`;
  const password = `e2e-${randomBytes(18).toString('base64url')}`;

  let link = '';
  await test.step('administrator creates an invitation', async () => {
    await page.goto('/operators');
    await page.getByRole('button', { name: 'Invite' }).click();
    const dialog = page.getByRole('dialog', { name: 'Invite operator' });
    await dialog.getByLabel('Email').fill(email);
    await dialog.getByRole('combobox', { name: 'Roles' }).click();
    await page
      .locator('.ant-select-dropdown:visible .ant-select-item-option')
      .filter({ hasText: 'Approver' })
      .click();
    await page.keyboard.press('Escape'); // close the multi-select dropdown, keep the dialog
    await dialog.getByRole('button', { name: 'Create invitation' }).click();
    const shown = page.getByRole('dialog', { name: 'Invitation link' });
    link =
      (await shown.getByRole('list', { name: 'Invitation link' }).locator('code').first().textContent()) ??
      '';
    expect(link).toContain('/invite/');
    expect(link.startsWith(e2eUrl ?? '')).toBe(true);
  });

  const invitee = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const p = await invitee.newPage();
  await test.step('invitee accepts the link and chooses a password', async () => {
    await p.goto(link);
    await expect(p.getByRole('heading', { name: 'Join HallPass' })).toBeVisible();
    await p.getByLabel('Display name').fill('Invited Approver');
    await p.getByLabel('Password', { exact: true }).fill(password);
    await p.getByLabel('Confirm password').fill(password);
    await p.getByRole('button', { name: 'Create account' }).click();
    await expect(p.getByText('Account created')).toBeVisible();
  });

  await test.step('invitee signs in, enrolls TOTP and gets the invited role', async () => {
    await p.getByRole('button', { name: 'Sign in' }).click();
    await p.getByRole('textbox', { name: 'Email' }).fill(email);
    await p.getByLabel('Password', { exact: true }).fill(password);
    await p.getByRole('button', { name: 'Sign in' }).click();
    await completeMfa(p);
    await expect(p.getByRole('navigation', { name: 'Main' })).toBeVisible();
    const me = (await (await p.request.get('/api/v1/me')).json()) as {
      operator: { email: string; roles: string[] };
    };
    expect(me.operator.email).toBe(email);
    expect([...me.operator.roles].sort()).toEqual(['approver', 'viewer']); // Viewer is preselected
  });

  await test.step('the invitation link is single use', async () => {
    const again = await browser.newContext({ storageState: { cookies: [], origins: [] } });
    const q = await again.newPage();
    await q.goto(link);
    await q.getByLabel('Display name').fill('Second Use');
    await q.getByLabel('Password', { exact: true }).fill(password);
    await q.getByLabel('Confirm password').fill(password);
    await q.getByRole('button', { name: 'Create account' }).click();
    await expect(q.getByRole('alert')).toBeVisible();
    await expect(q.getByText('Account created')).toHaveCount(0);
    await again.close();
  });

  await test.step('the administrator sees the new operator', async () => {
    await page.goto('/operators');
    await expect(page.getByRole('cell', { name: email }).first()).toBeVisible();
  });
  await invitee.close();
});

/**
 * Linking a chat account for approvals: an administrator adds a Telegram integration, the operator issues a link
 * code on their account page, and the bot receives "/link <code>" in a private chat. The update is delivered to the
 * integration's webhook with its secret token, as Telegram would; no live Telegram is involved.
 */
test('link a Telegram account with a one-time code', async ({ page }) => {
  test.setTimeout(120_000);
  trackApiRequests(page);
  await throttle(150);
  const name = `e2e-telegram-${Date.now().toString(36)}`;
  const botToken = `${String(100000000 + Math.floor(Math.random() * 800000000))}:${randomBytes(27).toString('base64url').slice(0, 35)}`;
  const webhookSecret = randomBytes(24).toString('base64url');
  const telegramUser = 5_000_000_000 + Math.floor(Math.random() * 1_000_000);

  await test.step('administrator adds a Telegram integration', async () => {
    await page.goto('/settings/integrations');
    await page.getByRole('button', { name: 'New integration' }).click();
    const drawer = page.getByRole('dialog', { name: 'New chat integration' });
    await drawer.locator('label.ant-radio-button-wrapper').filter({ hasText: 'Telegram' }).click();
    await drawer.getByLabel('Name', { exact: true }).fill(name);
    await drawer.getByLabel('Bot token', { exact: true }).fill(botToken);
    await drawer.getByLabel('Webhook secret', { exact: true }).fill(webhookSecret);
    await drawer.getByRole('button', { name: 'Create integration' }).click();
    await expect(page.getByText(`${name} · Telegram`)).toBeVisible();
  });

  const integrations = (await (await page.request.get('/api/v1/integrations')).json()) as {
    items: { name: string; webhook_path: string }[];
  };
  const webhook = integrations.items.find((i) => i.name === name)?.webhook_path ?? '';
  expect(webhook).toMatch(/^\/hooks\/telegram\//);

  let command = '';
  await test.step('operator creates a link code', async () => {
    await page.goto('/me');
    await page.getByRole('button', { name: 'Create Telegram link code' }).click();
    command = await page.getByRole('textbox', { name: 'Command to send' }).inputValue();
    expect(command).toMatch(/^\/link \S+$/);
  });

  await test.step('the bot receives the code in a private chat', async () => {
    const update = {
      update_id: Math.floor(Math.random() * 1_000_000_000),
      message: {
        message_id: 1,
        from: { id: telegramUser, is_bot: false, first_name: 'E2E' },
        chat: { id: telegramUser, type: 'private' },
        text: command,
      },
    };
    const wrong = await page.request.post(webhook, {
      data: update,
      headers: { 'X-Telegram-Bot-Api-Secret-Token': 'not-the-secret' },
    });
    expect(wrong.ok()).toBe(false);
    const res = await page.request.post(webhook, {
      data: update,
      headers: { 'X-Telegram-Bot-Api-Secret-Token': webhookSecret },
    });
    expect(res.status()).toBe(200);
  });

  await test.step('the account page lists the linked Telegram user', async () => {
    await page.reload();
    const table = page.getByRole('region', { name: 'My chat accounts' });
    await expect(table.getByRole('row').filter({ hasText: String(telegramUser) })).toBeVisible();
  });
});

const dex = {
  issuer: process.env.HP_E2E_DEX_ISSUER,
  clientId: process.env.HP_E2E_DEX_CLIENT_ID,
  clientSecret: process.env.HP_E2E_DEX_CLIENT_SECRET,
  email: process.env.HP_E2E_DEX_EMAIL,
  password: process.env.HP_E2E_DEX_PASSWORD,
};

/**
 * Single sign-on against a real identity provider (Dex, started by scripts/e2e.sh with E2E_DEX=1): an administrator
 * adds the provider with just-in-time provisioning limited to one IdP group and maps that group to the approver
 * role; a new operator then signs in through the IdP's own login page and lands in the console as an approver.
 */
test('sign in with SSO through a real identity provider', async ({ page, browser }) => {
  test.skip(!dex.issuer || !dex.password, 'needs E2E_DEX=1 (HP_E2E_DEX_*)');
  test.setTimeout(120_000);
  trackApiRequests(page);
  await throttle(150);

  await test.step('administrator adds the provider and a group mapping', async () => {
    await page.goto('/settings/auth');
    await page.getByRole('button', { name: 'Add provider' }).click();
    const drawer = page.getByRole('dialog', { name: 'Add SSO provider' });
    await drawer.getByLabel('Slug').fill('dex');
    await drawer.getByLabel('Display name').fill('Dex');
    await drawer.getByLabel('Issuer URL').fill(dex.issuer ?? '');
    await drawer.getByLabel('Client ID').fill(dex.clientId ?? '');
    await drawer.getByLabel('Client secret').fill(dex.clientSecret ?? '');
    const scopes = drawer.getByRole('combobox', { name: 'Scopes' });
    await scopes.fill('groups');
    await scopes.press('Enter');
    await drawer.getByLabel('Groups claim').fill('groups');
    await drawer.locator('label').filter({ hasText: 'Just-in-time' }).click();
    const required = drawer.getByRole('combobox', { name: 'Required groups' });
    await required.fill('hallpass-approvers');
    await required.press('Enter');
    // Dex runs on loopback: private endpoints must be allowed explicitly for this provider.
    await drawer.getByRole('button', { name: 'Advanced network settings' }).click();
    await drawer.getByRole('checkbox', { name: 'Allow private network endpoints' }).check();
    await drawer.getByRole('switch', { name: 'Enabled' }).click();
    await drawer.getByRole('button', { name: 'Create provider' }).click();
    await expect(page.getByRole('region', { name: 'SSO providers' }).getByText('Dex').first()).toBeVisible();

    const api = new Api(page);
    await api.init();
    const providers = await api.call<{ items: { id: string; slug: string }[] }>(
      'GET',
      '/api/v1/oidc-providers',
    );
    const id = providers.items.find((p) => p.slug === 'dex')?.id ?? '';
    await api.call('POST', `/api/v1/oidc-providers/${id}/mappings`, {
      group_value: 'hallpass-approvers',
      role: 'approver',
    });
  });

  const sso = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const p = await sso.newPage();
  await test.step('a new operator signs in through the IdP login page', async () => {
    await p.goto('/login');
    await p
      .getByRole('button', { name: 'Sign in with Dex' })
      .or(p.getByRole('link', { name: 'Sign in with Dex' }))
      .click();
    await expect(p).toHaveURL(new RegExp(`^${(dex.issuer ?? '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`));
    await p.locator('input[name="login"]').fill(dex.email ?? '');
    await p.locator('input[name="password"]').fill(dex.password ?? '');
    await p.locator('button[type="submit"]').click();
    await expect(p.getByRole('navigation', { name: 'Main' })).toBeVisible();
    const me = (await (await p.request.get('/api/v1/me')).json()) as {
      operator: { email: string; roles: string[] };
      session: { method: string };
    };
    expect(me.session.method).toBe('oidc');
    expect(me.operator.email).toBe(dex.email);
    expect(me.operator.roles).toEqual(['approver']);
  });
  await sso.close();
});
