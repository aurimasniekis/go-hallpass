import { expect, test } from '@playwright/test';

import { requireBackend, STORAGE_STATE } from './env';
import { throttle, trackApiRequests } from './throttle';
import { gatewaySsh, generateAgentKey, sshAddr, writeKnownHosts } from './ssh';

requireBackend();
test.use({ storageState: STORAGE_STATE });
test.describe.configure({ mode: 'serial' });

/**
 * Operator workflows against a real backend (PLAN §18.3/§18.4): register an agent with a key generated at
 * test time, enroll a server and a role, add a policy rule, then let the agent request access over SSH
 * (HALLPASS_E2E_SSH) and approve it in the UI. Names are unique per browser project.
 */
test('register agent, enroll server and role, allow by policy, approve an SSH request', async ({
  page,
}, testInfo) => {
  test.setTimeout(240_000);
  trackApiRequests(page);
  await throttle(150);
  const suffix = `${testInfo.project.name}-${Date.now().toString(36)}`.toLowerCase();
  const agentName = `e2e-agent-${suffix}`;
  const serverAlias = `e2e-srv-${suffix}`.slice(0, 40);
  const key = await generateAgentKey(agentName);

  await test.step('create agent with its public key', async () => {
    await page.goto('/agents');
    await page.getByRole('button', { name: 'New agent' }).click();
    const dialog = page.getByRole('dialog', { name: 'New agent' });
    await dialog.getByLabel('Name').fill(agentName);
    await dialog.getByLabel('Public keys').fill(key.publicKey);
    await dialog.getByRole('button', { name: 'Create agent' }).click();
    await expect(page).toHaveURL(/\/agents\/[^/]+$/);
    await expect(page.getByRole('heading', { level: 1, name: new RegExp(agentName) })).toBeVisible();
    await expect(page.getByText(/SHA256:/).first()).toBeVisible();
  });

  await test.step('create server and role', async () => {
    await page.goto('/servers');
    await page.getByRole('button', { name: 'New server' }).click();
    const dialog = page.getByRole('dialog', { name: 'New server' });
    await dialog.getByLabel('Alias').fill(serverAlias);
    await dialog.getByLabel('Address').fill('127.0.0.1');
    await dialog.getByLabel('Port').fill('22');
    await dialog.getByRole('button', { name: 'Create server' }).click();
    await expect(page).toHaveURL(/\/servers\/[^/?]+/);
    await page.getByRole('tab', { name: 'Roles' }).click();
    await page.getByRole('button', { name: 'New role' }).click();
    const roleDialog = page.getByRole('dialog', { name: 'New role' });
    await roleDialog.getByLabel('Alias').fill('ops');
    await roleDialog.getByLabel('Remote user').fill('deploy');
    await roleDialog.getByRole('button', { name: 'Create role' }).click();
    await expect(page.getByRole('cell', { name: 'ops' }).first()).toBeVisible();
    // Durations are shown human-readably (role default 30 minutes).
    await expect(page.getByText('30m').first()).toBeVisible();
  });

  await test.step('add a requestable policy rule', async () => {
    await page.goto('/policy');
    await page.getByRole('button', { name: 'New rule' }).click();
    const drawer = page.getByRole('dialog').filter({ has: page.getByRole('form', { name: 'Access rule' }) });
    await drawer.getByLabel('Name', { exact: true }).fill(`e2e-${suffix}`);
    await drawer.getByRole('checkbox', { name: /All agents/ }).check();
    await drawer.getByRole('checkbox', { name: /All servers/ }).check();
    await drawer.getByRole('checkbox', { name: /All roles/ }).check();
    await drawer.getByRole('button', { name: 'Create rule' }).click();
    await expect(page.getByRole('cell', { name: `e2e-${suffix}` }).first()).toBeVisible();
  });

  await test.step('grant approval authority with an approver rule', async () => {
    // Even administrators decide only within an approver rule's scope (HP-POL-011).
    await page.getByRole('tab', { name: 'Approver rules' }).click();
    await page.getByRole('button', { name: 'New approver rule' }).click();
    const drawer = page
      .getByRole('dialog')
      .filter({ has: page.getByRole('form', { name: 'Approver rule' }) });
    await drawer.getByLabel('Name', { exact: true }).fill(`e2e-approvers-${suffix}`);
    await drawer.getByRole('checkbox', { name: /All operators/ }).check();
    await drawer.getByRole('checkbox', { name: /All servers/ }).check();
    await drawer.getByRole('checkbox', { name: /All roles/ }).check();
    await drawer.getByRole('button', { name: 'Create approver rule' }).click();
    await expect(page.getByRole('cell', { name: `e2e-approvers-${suffix}` }).first()).toBeVisible();
  });

  if (!sshAddr) {
    testInfo.annotations.push({
      type: 'skipped-step',
      description: 'HALLPASS_E2E_SSH unset: no agent request',
    });
    return;
  }

  let requestId = '';
  await test.step('agent requests access over SSH', async () => {
    const knownHosts = await writeKnownHosts(page.request);
    const res = await gatewaySsh(key, knownHosts, [
      'request',
      serverAlias,
      '--role',
      'ops',
      // OpenSSH joins argv with spaces; the gateway tokenizer honors single quotes.
      "--reason='e2e check of the approval flow'",
      '--json',
    ]);
    expect(res.code, `${res.stdout}\n${res.stderr}`).toBe(0);
    const match = /req_[0-9a-z]{26}/.exec(res.stdout);
    expect(match, res.stdout).not.toBeNull();
    requestId = match?.[0] ?? '';
  });

  await test.step('approve in the UI; the server confirms the grant', async () => {
    await page.goto(`/requests/${requestId}`);
    await expect(page.getByText('e2e check of the approval flow')).toBeVisible();
    await page.getByRole('button', { name: 'Approve', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Approve access request' });
    await dialog.getByRole('button', { name: 'Approve' }).click();
    await expect(page.getByText('Approved by the server')).toBeVisible();
  });

  await test.step('grant appears under Sessions → Grants', async () => {
    await page.goto('/sessions?tab=grants&state=active');
    await expect(page.getByRole('tab', { name: 'Grants', selected: true })).toBeVisible();
    await expect(page.getByText(serverAlias).first()).toBeVisible();
  });
});

test('dashboard shows real status and the lockdown control requires a typed phrase', async ({ page }) => {
  trackApiRequests(page);
  await throttle(250);
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Dashboard' })).toBeVisible();
  const enable = page.getByRole('button', { name: /lockdown/i }).first();
  await enable.click();
  const confirm = page
    .getByRole('dialog')
    .getByRole('button', { name: /lockdown/i })
    .last();
  await expect(confirm).toBeDisabled();
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
});
