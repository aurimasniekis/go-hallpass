import { execFile, execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { promisify } from 'node:util';

import { expect, test } from '@playwright/test';

import { Api } from './api';
import { requireBackend, stateFile, STORAGE_STATE } from './env';
import { gatewaySsh, generateAgentKey, sshAddr, writeKnownHosts } from './ssh';
import { trackApiRequests } from './throttle';

requireBackend();
test.use({ storageState: STORAGE_STATE });
test.describe.configure({ mode: 'serial' });

/** Throwaway OpenSSH destination started by scripts/e2e.sh with E2E_DEST=1. */
const dest = process.env.HP_E2E_DEST;
const container = process.env.HP_E2E_DEST_CONTAINER;

interface Id {
  id: string;
}

/**
 * Review of recorded activity against a real destination: an auto-approved agent runs a command and uploads a file
 * with scp; the operator opens the access session, reads the timeline (command, file upload with its checksum) and
 * replays the recorded command output in the browser.
 */
test('timeline and replay of a recorded command and a file upload', async ({ page }, testInfo) => {
  test.skip(!dest || !container || !sshAddr, 'needs E2E_DEST=1 (HP_E2E_DEST) and HALLPASS_E2E_SSH');
  test.setTimeout(180_000);
  trackApiRequests(page);
  const api = new Api(page);
  await api.init();
  const suffix = `${testInfo.project.name}-${Date.now().toString(36)}`.toLowerCase();
  const alias = `rec-${suffix}`.slice(0, 40);
  const key = await generateAgentKey(`rec-agent-${suffix}`);
  const [destHost, destPort] = (dest ?? '').split(':');
  let serverId = '';

  await test.step('enroll the destination, a role and an auto-approve rule', async () => {
    const agent = await api.call<Id>('POST', '/api/v1/agents', {
      name: `rec-agent-${suffix}`,
      public_keys: [key.publicKey],
    });
    const server = await api.call<Id>('POST', '/api/v1/servers', {
      alias,
      address: destHost,
      port: Number(destPort),
    });
    serverId = server.id;
    const scanned = await api.call<{ items: Id[] }>(
      'POST',
      `/api/v1/servers/${server.id}/host-identities:scan`,
    );
    for (const h of scanned.items) {
      await api.call('POST', `/api/v1/host-identities/${h.id}/confirm`);
    }
    const role = await api.call<Id>('POST', `/api/v1/servers/${server.id}/roles`, {
      alias: 'inspect',
      remote_user: 'ro',
      capabilities: ['exec', 'file-transfer'],
    });
    const cred = await api.call<Id & { authorized_keys_line: string }>(
      'POST',
      `/api/v1/roles/${role.id}/credentials:generate`,
    );
    // Docker's port publishing rewrites the source address, so the from= option is dropped for this container.
    const line = cred.authorized_keys_line.replace(/from="[^"]*",?/, '').replace(/,(\s)/, '$1');
    execFileSync('docker', [
      'exec',
      container ?? '',
      'sh',
      '-c',
      `printf '%s\\n' '${line}' >> /home/ro/.ssh/authorized_keys`,
    ]);
    await api.call('POST', `/api/v1/credentials/${cred.id}/probe`);
    await api.call('POST', `/api/v1/credentials/${cred.id}/activate`);
    await api.call('POST', '/api/v1/policy/rules', {
      name: `rec-${suffix}`,
      enabled: true,
      effect: 'allow',
      level: 'auto_approve',
      require_reason: false,
      subjects: { agents: [agent.id] },
      targets: { servers: [server.id] },
      roles: { all: true },
      auto_max_duration: 3600,
    });
  });

  const knownHosts = await writeKnownHosts(page.request);
  await test.step('the agent runs a command and uploads a file', async () => {
    const res = await gatewaySsh(key, knownHosts, [
      'exec',
      alias,
      '--role',
      'inspect',
      // Another spec's catch-all rule may require a reason; scp then reuses the grant this creates.
      "--reason='e2e replay check'",
      '--',
      'echo',
      'replay-marker-$((6*7))',
    ]);
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toBe('replay-marker-42\n');

    const file = stateFile(`upload-${suffix}.txt`);
    writeFileSync(file, 'uploaded through the gateway\n');
    const [host, port] = (sshAddr ?? '').split(':');
    await promisify(execFile)('scp', [
      '-F',
      '/dev/null',
      '-P',
      port ?? '22',
      '-i',
      key.privatePath,
      '-o',
      'IdentitiesOnly=yes',
      '-o',
      'BatchMode=yes',
      '-o',
      `UserKnownHostsFile=${knownHosts}`,
      '-o',
      'StrictHostKeyChecking=yes',
      file,
      `${alias}@${host ?? '127.0.0.1'}:/tmp/e2e-upload.txt`,
    ]);
  });

  await test.step('the session timeline shows the command and the upload', async () => {
    let sessionId = '';
    await expect
      .poll(async () => {
        const list = await api.call<{ items: (Id & { server_id: string; state: string })[] }>(
          'GET',
          '/api/v1/access-sessions',
        );
        sessionId = list.items.find((s) => s.server_id === serverId)?.id ?? '';
        return sessionId;
      })
      .not.toBe('');
    await page.goto(`/sessions/${sessionId}`);
    const timeline = page
      .locator('.ant-card')
      .filter({ has: page.getByText('Timeline', { exact: true }) })
      .last();
    await expect(timeline.getByText('Command requested by the agent').first()).toBeVisible();
    await expect(timeline.getByText(/Uploaded \/tmp\/e2e-upload\.txt \(29 B\)/)).toBeVisible({
      timeout: 30_000,
    });
    await expect(timeline.getByText(/File transfer finished: 1 file/)).toBeVisible();
  });

  await test.step('the recorded command output replays in the browser', async () => {
    const replay = page
      .locator('.ant-card')
      .filter({ has: page.getByText('Replay', { exact: true }) })
      .first();
    await replay.scrollIntoViewIfNeeded();
    await replay.getByRole('combobox', { name: 'Channel to replay' }).click();
    await page.locator('.ant-select-dropdown:visible .ant-select-item-option').first().click();
    await replay.getByRole('button', { name: 'Load recording' }).click();
    await expect(replay.getByText('echo replay-marker-$((6*7))')).toBeVisible();
    await replay.getByRole('button', { name: 'Play' }).click();
    await expect(replay.getByRole('button', { name: 'Replay' })).toBeVisible({ timeout: 60_000 });
    await expect(replay.locator('.xterm-rows').first()).toContainText('replay-marker-42');
  });
});
