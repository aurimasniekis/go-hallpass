import { execFile, execFileSync, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { expect, test, type Browser, type Locator, type Page } from '@playwright/test';

import { Api } from './api';
import { e2eUrl, saveAdmin } from './env';
import { type AgentKey, gatewaySsh, generateAgentKey, sshAddr, writeKnownHosts } from './ssh';
import { trackApiRequests } from './throttle';
import { freshTotp } from './totp';

/**
 * Documentation screenshots (scripts/screenshots.sh). Runs only when HP_SCREENSHOTS_OUT is set, against a fresh
 * backend and the throwaway sshd containers `hallpass-docs-{web1,db1,ci-runner,forge}` on 127.0.0.1:2431-2434. API calls
 * and backups go to fakes that answer as api.github.com and s3.example.com (scripts/screenshots.sh). Every name, reason
 * and file is fictional; agent keys are generated at run time. Agent outputs in the terminal images are real.
 */
const OUT = process.env.HP_SCREENSHOTS_OUT ?? '';
const HALLPASS_API = process.env.HP_DOCS_HALLPASS_API ?? '';
const DOCS_CA = process.env.HP_DOCS_CA_PEM ?? '';
test.skip(
  !OUT || !e2eUrl || !sshAddr || !HALLPASS_API || !DOCS_CA,
  'HP_SCREENSHOTS_OUT, HP_DOCS_*, HALLPASS_E2E_URL and HALLPASS_E2E_SSH are required (run scripts/screenshots.sh)',
);
test.describe.configure({ mode: 'serial' });

const MIN = 60;
const HOUR = 3600;

interface Id {
  id: string;
}
interface Credential extends Id {
  authorized_keys_line: string;
}
interface HostIdentity extends Id {
  state: string;
}
interface AccessRequest extends Id {
  agent_id: string;
  server_id: string;
  role_id: string;
  state: string;
}
interface AccessSession extends Id {
  agent_id: string;
  server_id: string;
  role_id: string;
}

/** Interactive `ssh -tt` session as an agent: send lines, wait for the prompt, collect everything printed. */
class Pty {
  private buf = '';
  private readonly proc;
  readonly done: Promise<number>;

  constructor(key: AgentKey, knownHosts: string, words: string[]) {
    const [host, port] = (sshAddr ?? '').split(':');
    this.proc = spawn('ssh', [
      '-F',
      '/dev/null',
      '-tt',
      '-p',
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
      `agent@${host ?? '127.0.0.1'}`,
      ...words,
    ]);
    const add = (d: Buffer) => {
      this.buf += d.toString('utf8');
    };
    this.proc.stdout.on('data', add);
    this.proc.stderr.on('data', add);
    this.done = new Promise((resolve) => {
      this.proc.on('close', (code) => {
        resolve(code ?? -1);
      });
    });
  }

  get text(): string {
    return cleanTerminal(this.buf);
  }

  async prompt(): Promise<void> {
    const deadline = Date.now() + 60_000;
    while (!this.text.endsWith('$ ')) {
      if (Date.now() > deadline) {
        throw new Error(`no shell prompt within 60 s; output so far:\n${this.text}`);
      }
      await sleep(100);
    }
  }

  async run(line: string, pause = 900): Promise<void> {
    await this.prompt();
    await sleep(pause);
    this.proc.stdin.write(`${line}\n`);
    await sleep(300);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Plain text from a terminal stream: no escape sequences, no carriage returns. */
function cleanTerminal(s: string): string {
  return s
    .replace(/\x1b\][^\x07]*(\x07|\x1b\\)/g, '') // eslint-disable-line no-control-regex
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '') // eslint-disable-line no-control-regex
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '');
}

function docker(container: string, script: string): void {
  execFileSync('docker', ['exec', container, 'sh', '-c', script]);
}

/** Installs a login key for `user` without the `from=` option (Docker's port publishing rewrites the source address). */
function installKey(host: string, user: string, line: string): void {
  const entry = line.replace(/from="[^"]*",?/, '').replace(/,(\s)/, '$1');
  docker(`hallpass-docs-${host}`, `printf '%s\\n' '${entry}' >> /home/${user}/.ssh/authorized_keys`);
}

async function shot(
  page: Page,
  name: string,
  opts: { mask?: Locator[]; fullPage?: boolean } = {},
): Promise<void> {
  await page.waitForLoadState('networkidle');
  await page.evaluate(() => document.fonts.ready);
  await sleep(400);
  await page.screenshot({
    path: join(OUT, `${name}.png`),
    animations: 'disabled',
    caret: 'hide',
    maskColor: '#c9ced6',
    ...opts,
  });
}

/** Light and dark captures for `<Shot themed>`; `prepare` runs again after the theme switch. */
async function themed(page: Page, name: string, prepare?: () => Promise<void>): Promise<void> {
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    if (prepare) {
      await prepare();
    }
    await shot(page, `${name}-${scheme}`);
  }
  await page.emulateMedia({ colorScheme: 'light' });
}

/** A fixed 1216×900 region starting at a card, for the narrower session images. */
async function cardShot(page: Page, card: Locator, name: string): Promise<void> {
  await card.scrollIntoViewIfNeeded();
  await page.waitForLoadState('networkidle');
  await sleep(400);
  const box = await card.boundingBox();
  if (!box) {
    throw new Error(`${name}: card not visible`);
  }
  const scrollY = await page.evaluate(() => window.scrollY);
  await page.screenshot({
    path: join(OUT, `${name}.png`),
    animations: 'disabled',
    fullPage: true,
    clip: { x: box.x - 24, y: box.y + scrollY - 16, width: 1216, height: 900 },
  });
}

async function pickOption(page: Page, combobox: Locator, label: string): Promise<void> {
  await combobox.click();
  await page
    .locator('.ant-select-dropdown:visible .ant-select-item-option')
    .filter({ hasText: label })
    .first()
    .click();
}

/** Renders an agent transcript as a terminal window (agent-terminal.png, agent-shell.png). */
async function terminalShot(browser: Browser, name: string, title: string, lines: string[]): Promise<void> {
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const body = lines
    .map((l) => {
      if (l.startsWith('$ ')) {
        return `<span class="p">$</span> ${esc(l.slice(2))}`;
      }
      if (/^(gh: )?hallpass(-api)?:/.test(l)) {
        return `<span class="g">${esc(l)}</span>`;
      }
      if (/^\[exit \d+\]$/.test(l)) {
        return `<span class="x">${esc(l)}</span>`;
      }
      return esc(l);
    })
    .join('\n');
  const ctx = await browser.newContext({ viewport: { width: 837, height: 400 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.setContent(`<!doctype html><html><head><style>
    body { margin: 0; background: #e8ecf1; }
    .wrap { padding: 21px; display: inline-block; }
    .win { width: 795px; border-radius: 10px; overflow: hidden; background: #111827;
      box-shadow: 0 10px 30px rgba(15, 23, 42, .18); }
    .bar { position: relative; height: 26px; background: #1f2937; color: #cbd5e1;
      font: 500 10px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 26px; text-align: center; }
    .dots { position: absolute; left: 10px; top: 8px; display: flex; gap: 6px; }
    .dots i { width: 9px; height: 9px; border-radius: 50%; display: block; }
    pre { margin: 0; padding: 14px 13px 16px; color: #e5e7eb; white-space: pre-wrap; word-break: break-all;
      font: 10.5px/15px "SF Mono", Menlo, Consolas, monospace; }
    .p { color: #4ade80; } .g { color: #facc15; } .x { color: #94a3b8; }
  </style></head><body><div class="wrap"><div class="win"><div class="bar"><span class="dots">
    <i style="background:#ef4444"></i><i style="background:#f59e0b"></i><i style="background:#22c55e"></i></span>
    ${esc(title)}</div><pre>${body}</pre></div></div></body></html>`);
  await page.locator('.wrap').screenshot({ path: join(OUT, `${name}.png`) });
  await ctx.close();
}

/** Runs an agent-side tool; output is stderr followed by stdout. */
function runTool(
  file: string,
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    execFile(file, args, { cwd, timeout: 300_000, env }, (error, stdout, stderr) => {
      const code = error ? (typeof error.code === 'number' ? error.code : 1) : 0;
      resolve({ code, out: stderr + stdout });
    });
  });
}

/** Runs the system git as an agent whose ssh config calls the gateway `center`, ignoring the developer's git config. */
function runGit(args: string[], cwd: string, sshConfig: string): Promise<{ code: number; out: string }> {
  const who = { name: 'claude-sre', email: 'claude-sre@example.com' };
  return runTool('git', args, cwd, {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -F ${sshConfig}`,
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    GIT_AUTHOR_NAME: who.name,
    GIT_AUTHOR_EMAIL: who.email,
    GIT_COMMITTER_NAME: who.name,
    GIT_COMMITTER_EMAIL: who.email,
  });
}

/**
 * The environment of an agent running hallpass-api and gh: the developer's gh login, proxy settings and HallPass or
 * Claude Code session are left out, so the run neither uses them nor shows them.
 */
function agentToolEnv(home: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (
      !/^(GH_|GITHUB_|HALLPASS_|CLAUDE_|HTTPS?_PROXY$|https?_proxy$|NO_PROXY$|no_proxy$|SSL_CERT_)/.test(k)
    ) {
      env[k] = v;
    }
  }
  return {
    ...env,
    HOME: home,
    GH_CONFIG_DIR: join(home, 'gh'),
    GH_PROMPT_DISABLED: '1',
    GH_NO_UPDATE_NOTIFIER: '1',
  };
}

function outputLines(s: string): string[] {
  return cleanTerminal(s).replace(/\n+$/, '').split('\n');
}

test('documentation screenshots', async ({ page, browser }) => {
  test.setTimeout(30 * 60_000);
  trackApiRequests(page);
  await page.emulateMedia({ colorScheme: 'light' });

  // ---- First administrator and MFA enrollment -------------------------------------------------------------------
  const admin = {
    email: 'ada@example.com',
    password: `docs-${randomBytes(18).toString('base64url')}`,
    totpSecret: '',
  };
  await page.goto(`/setup?token=${encodeURIComponent(process.env.HALLPASS_E2E_SETUP_TOKEN ?? '')}`);
  await expect(page).toHaveURL(/\/setup$/);
  await page.getByRole('textbox', { name: 'Email' }).fill(admin.email);
  await page.getByLabel('Display name').fill('Ada Lovelace');
  await page.getByLabel('Password', { exact: true }).fill(admin.password);
  await page.getByLabel('Confirm password').fill(admin.password);
  await shot(page, 'setup-admin');
  await page.getByRole('button', { name: 'Create administrator' }).click();
  const secret = page.getByLabel('Secret', { exact: true });
  await expect(secret).toHaveValue(/^[A-Z2-7]+=*$/);
  admin.totpSecret = await secret.inputValue();
  saveAdmin(admin);
  await shot(page, 'mfa-enroll', { mask: [page.getByLabel('Authenticator QR code'), secret] });
  await page.getByLabel('Code from your app').fill(await freshTotp(admin.totpSecret));
  await page.getByRole('button', { name: 'Confirm' }).click();
  const codes = page.getByRole('dialog', { name: 'Recovery codes' });
  await codes.getByRole('checkbox', { name: 'I have stored this securely' }).check();
  await codes.getByRole('button', { name: 'Done' }).click();
  await page.getByLabel('Authentication code').fill(await freshTotp(admin.totpSecret));
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  const api = new Api(page);
  await api.init();

  // ---- Guided onboarding, first step (not submitted; the servers are created through the API) --------------------
  await page.goto('/servers/onboard');
  await page.getByLabel('Alias').fill('web1');
  await page.getByLabel('Address').fill('127.0.0.1');
  await page.getByLabel('Port').fill('2431');
  await shot(page, 'wizard-server');

  // ---- Inventory --------------------------------------------------------------------------------------------------
  const agentSpecs = [
    {
      name: 'claude-sre',
      description: 'Claude Code SRE assistant (on-call runbooks)',
      groups: ['sre-agents'],
      labels: { team: 'sre' },
    },
    {
      name: 'deploy-bot',
      description: 'Release automation',
      groups: ['release-agents'],
      labels: { team: 'platform' },
    },
    {
      name: 'ci-agent',
      description: 'Build and test agent',
      groups: ['ci-agents'],
      labels: { team: 'platform' },
    },
  ];
  const keys: Record<string, AgentKey> = {};
  const agents: Record<string, string> = {};
  for (const a of agentSpecs) {
    keys[a.name] = await generateAgentKey(a.name);
    agents[a.name] = (
      await api.call<Id>('POST', '/api/v1/agents', { ...a, public_keys: [keys[a.name]?.publicKey] })
    ).id;
  }

  const serverSpecs = [
    {
      alias: 'web1',
      display_name: 'web1',
      description: 'Public web front end (nginx)',
      environment: 'production',
      port: 2431,
      groups: ['prod-web'],
      labels: { env: 'prod', tier: 'web' },
    },
    {
      alias: 'db1',
      display_name: 'db1',
      description: 'PostgreSQL primary for the shop',
      environment: 'production',
      port: 2432,
      groups: ['prod-db'],
      labels: { env: 'prod', tier: 'db' },
    },
    {
      alias: 'ci-runner',
      display_name: 'ci-runner',
      description: 'Build runner',
      environment: 'ci',
      port: 2433,
      groups: ['ci'],
      labels: { env: 'ci' },
    },
  ];
  const servers: Record<string, string> = {};
  for (const s of serverSpecs) {
    const id = (await api.call<Id>('POST', '/api/v1/servers', { ...s, address: '127.0.0.1' })).id;
    servers[s.alias] = id;
    const scanned = await api.call<{ items: HostIdentity[] }>(
      'POST',
      `/api/v1/servers/${id}/host-identities:scan`,
    );
    for (const h of scanned.items) {
      await api.call('POST', `/api/v1/host-identities/${h.id}/confirm`);
    }
  }

  const roleSpecs = [
    {
      server: 'web1',
      alias: 'inspect',
      remote_user: 'ro',
      description: 'Read logs and service status. No sudo.',
      default_duration: 30 * MIN,
      max_duration: 2 * HOUR,
    },
    {
      server: 'web1',
      alias: 'deploy',
      remote_user: 'deploy',
      description: 'Deploy releases into /srv/app and reload the app.',
      default_duration: HOUR,
      max_duration: 4 * HOUR,
    },
    {
      server: 'db1',
      alias: 'inspect',
      remote_user: 'ro',
      description: 'Read PostgreSQL logs and system status. No database superuser.',
      default_duration: 30 * MIN,
      max_duration: 2 * HOUR,
    },
    {
      server: 'db1',
      alias: 'maintenance',
      remote_user: 'deploy',
      description: 'Run VACUUM, REINDEX and restart PostgreSQL.',
      default_duration: HOUR,
      max_duration: 4 * HOUR,
    },
    {
      server: 'ci-runner',
      alias: 'deploy',
      remote_user: 'deploy',
      description: 'Run build jobs.',
      default_duration: HOUR,
      max_duration: 4 * HOUR,
    },
  ];
  const creds: { server: string; user: string; cred: Credential }[] = [];
  const roleIds: Record<string, string> = {};
  for (const r of roleSpecs) {
    const { server, ...body } = r;
    const role = await api.call<Id>('POST', `/api/v1/servers/${servers[server] ?? ''}/roles`, {
      ...body,
      capabilities: ['exec', 'shell', 'pty'],
    });
    roleIds[`${server}/${r.alias}`] = role.id;
    const cred = await api.call<Credential>('POST', `/api/v1/roles/${role.id}/credentials:generate`);
    creds.push({ server, user: r.remote_user, cred });
  }

  // Wizard, login step: web1's inspect key is installed and tested, deploy's key still waits for installation.
  const [web1Inspect] = creds;
  if (!web1Inspect) {
    throw new Error('no credentials');
  }
  installKey('web1', 'ro', web1Inspect.cred.authorized_keys_line);
  await api.call('POST', `/api/v1/credentials/${web1Inspect.cred.id}/probe`);
  await page.goto(`/servers/onboard?server=${servers.web1 ?? ''}&step=credentials`);
  await shot(page, 'wizard-credentials', { fullPage: true });
  for (const c of creds) {
    if (c !== web1Inspect) {
      installKey(c.server, c.user, c.cred.authorized_keys_line);
      await api.call('POST', `/api/v1/credentials/${c.cred.id}/probe`);
    }
    await api.call('POST', `/api/v1/credentials/${c.cred.id}/activate`);
  }
  // Access step filled in and submitted through the wizard, so the summary shows a covered server.
  await page.goto(`/servers/onboard?server=${servers.web1 ?? ''}&step=access`);
  const agentGroups = page.getByRole('combobox', { name: 'Agent groups' });
  await agentGroups.fill('sre-agents');
  await agentGroups.press('Enter');
  await page.keyboard.press('Escape');
  // Only deploy needs approval; inspect stays auto-approved by the policy rules below.
  await page.getByRole('checkbox', { name: 'inspect (ro)' }).uncheck();
  await page.getByRole('heading', { name: 'Set up web1' }).click();
  await shot(page, 'wizard-access', { fullPage: true });
  await page.getByRole('button', { name: 'Create access rules' }).click();
  await expect(page.getByText('6. Summary')).toBeVisible();

  // ---- Policy -----------------------------------------------------------------------------------------------------
  const rule = (r: Record<string, unknown>) =>
    api.call('POST', '/api/v1/policy/rules', { enabled: true, require_reason: true, ...r });
  await rule({
    name: 'release bot never reaches databases',
    effect: 'deny',
    subjects: { agents: [agents['deploy-bot']] },
    targets: { server_labels: { matchLabels: { tier: 'db' } } },
    roles: { all: true },
  });
  await rule({
    name: 'SRE inspect production',
    effect: 'allow',
    level: 'auto_approve',
    require_reason: false,
    subjects: { agent_groups: ['sre-agents'] },
    targets: { server_labels: { matchLabels: { env: 'prod' } } },
    roles: { names: ['inspect'] },
    max_duration: 2 * HOUR,
    auto_max_duration: 30 * MIN,
  });
  await rule({
    name: 'SRE changes on request',
    effect: 'allow',
    level: 'requestable',
    subjects: { agent_groups: ['sre-agents'] },
    targets: { server_groups: ['prod-web', 'prod-db'] },
    roles: { names: ['deploy', 'maintenance'] },
    max_duration: 4 * HOUR,
  });
  await rule({
    name: 'release bot deploys web',
    effect: 'allow',
    level: 'requestable',
    subjects: { agents: [agents['deploy-bot']] },
    targets: { server_groups: ['prod-web'] },
    roles: { names: ['deploy'] },
    max_duration: 2 * HOUR,
  });
  await rule({
    name: 'CI uses its runner',
    effect: 'allow',
    level: 'auto_approve',
    require_reason: false,
    subjects: { agent_groups: ['ci-agents'] },
    targets: { server_groups: ['ci'] },
    roles: { all: true },
    auto_max_duration: HOUR,
  });
  await api.call('POST', '/api/v1/policy/approver-rules', {
    name: 'administrators approve everything',
    enabled: true,
    operators: { all: true },
    targets: { all: true },
    roles: { all: true },
  });
  await page.goto(`/servers/onboard?server=${servers.web1 ?? ''}&step=done`);
  await shot(page, 'wizard-done');

  // ---- Git remote: the forge container, a read profile for every acme repository and a push profile for two -------
  const forge = (
    await api.call<Id>('POST', '/api/v1/servers', {
      kind: 'git',
      alias: 'forge',
      description: 'Company git server (acme organization)',
      address: '127.0.0.1',
      port: 2434,
    })
  ).id;
  servers.forge = forge;
  const forgeKeys = await api.call<{ items: HostIdentity[] }>(
    'POST',
    `/api/v1/servers/${forge}/host-identities:scan`,
  );
  for (const h of forgeKeys.items) {
    await api.call('POST', `/api/v1/host-identities/${h.id}/confirm`);
  }
  const profileSpecs = [
    {
      alias: 'acme-read',
      description: 'Clone and fetch any acme repository.',
      capabilities: ['git-read'],
      git: { repos: ['acme/**'] },
      default_duration: 30 * MIN,
      max_duration: 2 * HOUR,
    },
    {
      alias: 'acme-push',
      description: 'Push agent/ branches to acme/api and acme/web. main stays protected.',
      capabilities: ['git-read', 'git-write'],
      git: { repos: ['acme/{api,web}'], push: { branches: ['agent/**'], protected_branches: ['main'] } },
      default_duration: HOUR,
      max_duration: 4 * HOUR,
    },
  ];
  for (const p of profileSpecs) {
    const role = await api.call<Id>('POST', `/api/v1/servers/${forge}/roles`, {
      ...p,
      remote_user: 'deploy',
    });
    roleIds[`forge/${p.alias}`] = role.id;
    const cred = await api.call<Credential>('POST', `/api/v1/roles/${role.id}/credentials:generate`);
    installKey('forge', 'deploy', cred.authorized_keys_line);
    await api.call('POST', `/api/v1/credentials/${cred.id}/probe`);
    await api.call('POST', `/api/v1/credentials/${cred.id}/activate`);
  }
  await rule({
    name: 'SRE reads acme repositories',
    effect: 'allow',
    level: 'auto_approve',
    require_reason: false,
    subjects: { agent_groups: ['sre-agents'] },
    targets: { servers: [forge] },
    roles: { names: ['acme-read'] },
    max_duration: 2 * HOUR,
    auto_max_duration: 30 * MIN,
  });
  await rule({
    name: 'SRE pushes agent branches on request',
    effect: 'allow',
    level: 'requestable',
    subjects: { agent_groups: ['sre-agents'] },
    targets: { servers: [forge] },
    roles: { names: ['acme-push'] },
    max_duration: 4 * HOUR,
  });

  // ---- API target: GitHub (answered by the fake front), a read profile and one that may comment on issues ----------
  const github = (
    await api.call<Id>('POST', '/api/v1/servers', {
      kind: 'api',
      alias: 'github',
      description: 'GitHub REST API (acme organization)',
      api: {
        hosts: ['api.github.com', 'uploads.github.com', 'results-receiver.actions.githubusercontent.com'],
      },
    })
  ).id;
  servers.github = github;
  const apiProfileSpecs = [
    {
      alias: 'acme-read',
      description: 'Read repositories, issues and pull requests of the acme organization.',
      rules: [{ effect: 'allow', methods: ['GET', 'HEAD'], paths: ['/repos/acme/**'] }],
      default_duration: 30 * MIN,
      max_duration: 2 * HOUR,
    },
    {
      alias: 'acme-issues',
      description: 'Comment on acme issues. Never delete or administer repositories.',
      rules: [
        { effect: 'allow', methods: ['POST'], paths: ['/repos/acme/*/issues/*/comments'] },
        { effect: 'deny', methods: ['DELETE'] },
      ],
      default_duration: HOUR,
      max_duration: 4 * HOUR,
    },
  ];
  for (const { rules, ...p } of apiProfileSpecs) {
    const role = await api.call<Id>('POST', `/api/v1/servers/${github}/roles`, {
      ...p,
      capabilities: ['api'],
      api: { rules },
    });
    roleIds[`github/${p.alias}`] = role.id;
    await api.call('PUT', `/api/v1/roles/${role.id}/api-credential`, {
      type: 'bearer',
      secret: `docs-${randomBytes(18).toString('base64url')}`,
    });
  }
  await rule({
    name: 'SRE reads acme on GitHub',
    effect: 'allow',
    level: 'auto_approve',
    require_reason: false,
    subjects: { agent_groups: ['sre-agents'] },
    targets: { servers: [github] },
    roles: { names: ['acme-read'] },
    max_duration: 2 * HOUR,
    auto_max_duration: 30 * MIN,
  });
  await rule({
    name: 'SRE comments on GitHub issues on request',
    effect: 'allow',
    level: 'requestable',
    subjects: { agent_groups: ['sre-agents'] },
    targets: { servers: [github] },
    roles: { names: ['acme-issues'] },
    max_duration: 4 * HOUR,
  });

  // ---- File transfer: a web1 role that can only copy files (scp, sftp), recorded per operation --------------------
  const filesRole = await api.call<Id>('POST', `/api/v1/servers/${servers.web1 ?? ''}/roles`, {
    alias: 'files',
    remote_user: 'deploy',
    description: 'Copy build artifacts to and from /srv/app/incoming. No shell.',
    capabilities: ['file-transfer'],
    default_duration: 30 * MIN,
    max_duration: 2 * HOUR,
  });
  roleIds['web1/files'] = filesRole.id;
  const filesCred = await api.call<Credential>('POST', `/api/v1/roles/${filesRole.id}/credentials:generate`);
  installKey('web1', 'deploy', filesCred.authorized_keys_line);
  await api.call('POST', `/api/v1/credentials/${filesCred.id}/probe`);
  await api.call('POST', `/api/v1/credentials/${filesCred.id}/activate`);
  await rule({
    name: 'SRE copies files to web1',
    effect: 'allow',
    level: 'auto_approve',
    require_reason: false,
    subjects: { agent_groups: ['sre-agents'] },
    targets: { servers: [servers.web1] },
    roles: { names: ['files'] },
    max_duration: 2 * HOUR,
    auto_max_duration: 30 * MIN,
  });

  // ---- Agent activity over SSH ------------------------------------------------------------------------------------
  const knownHosts = await writeKnownHosts(page.request);
  const sre = keys['claude-sre'];
  const bot = keys['deploy-bot'];
  const ci = keys['ci-agent'];
  if (!sre || !bot || !ci) {
    throw new Error('missing agent keys');
  }
  const ssh = (key: AgentKey, words: string[]) => gatewaySsh(key, knownHosts, words);
  const pending = async (agent: string, server: string): Promise<AccessRequest> => {
    let found: AccessRequest | undefined;
    await expect
      .poll(
        async () => {
          const list = await api.call<{ items: AccessRequest[] }>('GET', '/api/v1/requests?state=pending');
          found = list.items.find((r) => r.agent_id === agents[agent] && r.server_id === servers[server]);
          return found !== undefined;
        },
        // Generous: each poll waits in the API throttle when the seeding above used up the per-minute budget.
        { timeout: 120_000 },
      )
      .toBe(true);
    if (!found) {
      throw new Error(`no pending request for ${agent} on ${server}`);
    }
    return found;
  };

  // claude-sre: database maintenance on request, approved by Ada.
  const maint = ssh(sre, [
    'request',
    'db1',
    '--role',
    'maintenance',
    "--reason='Vacuum the bloated cart_items table (OPS-2288)'",
  ]);
  await maint;
  await api.call('POST', `/api/v1/requests/${(await pending('claude-sre', 'db1')).id}/approve`, {
    duration: HOUR,
    comment: 'Go ahead, outside peak hours.',
  });

  const transcript: string[] = [];
  const record = async (
    shown: string,
    key: AgentKey,
    words: string[],
    during?: () => Promise<void>,
    into: string[] = transcript,
  ) => {
    const run = ssh(key, words);
    if (during) {
      await during();
    }
    const res = await run;
    into.push(
      `$ ${shown}`,
      ...(res.stderr ? outputLines(res.stderr) : []),
      ...(res.stdout ? outputLines(res.stdout) : []),
    );
    if (res.code !== 0) {
      into.push(`[exit ${String(res.code)}]`);
    }
    into.push('');
  };
  await record('ssh center list', sre, ['list']);
  await record('ssh center exec web1 --role inspect -- uptime', sre, [
    'exec',
    'web1',
    '--role',
    'inspect',
    '--',
    'uptime',
  ]);

  // Interactive, recorded shell (agent-shell.png and the replay screenshots).
  const shell = new Pty(sre, knownHosts, ['connect', 'web1', '--role', 'inspect']);
  for (const line of [
    'uptime',
    'ls -lh /var/log/nginx',
    "grep -c 'upstream timed out' /var/log/nginx/error.log",
    'ps -eo user,pid,stat,comm | head -5',
    'exit',
  ]) {
    await shell.run(line);
  }
  await shell.done;
  await terminalShot(
    browser,
    'agent-shell',
    'claude-sre@agent-sandbox: ssh -t center connect web1 --role inspect',
    shell.text.replace(/\n+$/, '').split('\n'),
  );

  await record(
    `ssh center 'exec web1 --role deploy --reason "Ship release 1.4.3 (OPS-2291)" -- ls /srv/app/releases'`,
    sre,
    [
      'exec',
      'web1',
      '--role',
      'deploy',
      `--reason='Ship release 1.4.3 (OPS-2291)'`,
      '--',
      'ls',
      '/srv/app/releases',
    ],
    async () => {
      await api.call('POST', `/api/v1/requests/${(await pending('claude-sre', 'web1')).id}/approve`, {
        duration: HOUR,
      });
    },
  );
  // A hidden server, with a terminal like the command shown: human-readable refusal instead of the JSON error.
  const hidden = new Pty(sre, knownHosts, ['connect', 'ci-runner']);
  const hiddenCode = await hidden.done;
  transcript.push('$ ssh -t center connect ci-runner', ...hidden.text.replace(/\n+$/, '').split('\n'));
  transcript.push(`[exit ${String(hiddenCode)}]`, '');
  await terminalShot(
    browser,
    'agent-terminal',
    'claude-sre@agent-sandbox: ssh center',
    transcript.slice(0, -1),
  );

  // ci-agent runs on its own runner automatically.
  await ssh(ci, ['exec', 'ci-runner', '--role', 'deploy', '--', 'uname', '-sr']);

  // claude-sre with plain git: clone through the auto-approved read profile, request the push profile with a reason,
  // push an agent branch, and get refused on the protected main branch.
  const gitHome = mkdtempSync(join(tmpdir(), 'hallpass-docs-git-'));
  const [gwHost, gwPort] = (sshAddr ?? '').split(':');
  const sshConfig = join(gitHome, 'ssh_config');
  writeFileSync(
    sshConfig,
    [
      'Host center',
      `  HostName ${gwHost ?? '127.0.0.1'}`,
      `  Port ${gwPort ?? '22'}`,
      '  User agent',
      `  IdentityFile ${sre.privatePath}`,
      '  IdentitiesOnly yes',
      `  UserKnownHostsFile ${knownHosts}`,
      '  StrictHostKeyChecking yes',
      '  BatchMode yes',
      '',
    ].join('\n'),
  );
  const gitTranscript: string[] = [];
  const git = async (shown: string, args: string[], cwd: string, want = 0) => {
    const res = await runGit(args, cwd, sshConfig);
    if (res.code !== want) {
      throw new Error(`git ${args.join(' ')}: exit ${String(res.code)}\n${res.out}`);
    }
    gitTranscript.push(`$ ${shown}`, ...(res.out ? outputLines(res.out) : []));
    if (res.code !== 0) {
      gitTranscript.push(`[exit ${String(res.code)}]`);
    }
    gitTranscript.push('');
  };
  await git('git clone center:forge/acme/api.git', ['clone', 'center:forge/acme/api.git'], gitHome);
  const repo = join(gitHome, 'api');
  const cartToml = join(repo, 'config', 'cart.toml');
  writeFileSync(cartToml, readFileSync(cartToml, 'utf8').replace('10s', '30s'));
  await git(
    `cd api && sed -i 's/10s/30s/' config/cart.toml && git commit -qam 'Raise the cart upstream timeout to 30s'`,
    ['commit', '-qam', 'Raise the cart upstream timeout to 30s'],
    repo,
  );
  await record(
    `ssh center 'request forge --role acme-push --reason "Push the cart timeout fix (OPS-2302)" --wait'`,
    sre,
    ['request', 'forge', '--role', 'acme-push', "--reason='Push the cart timeout fix (OPS-2302)'", '--wait'],
    async () => {
      await api.call('POST', `/api/v1/requests/${(await pending('claude-sre', 'forge')).id}/approve`, {
        duration: HOUR,
        comment: 'Branch only; I will review the merge request.',
      });
    },
    gitTranscript,
  );
  // Pin the push profile in the remote URL ("<remote>+<profile>"), so pushes never use another profile.
  await git(
    'git remote set-url origin forge+acme-push@center:forge/acme/api.git',
    ['remote', 'set-url', 'origin', 'forge+acme-push@center:forge/acme/api.git'],
    repo,
  );
  await git('git push origin HEAD:agent/cart-timeout', ['push', 'origin', 'HEAD:agent/cart-timeout'], repo);
  await git('git push origin HEAD:main', ['push', 'origin', 'HEAD:main'], repo, 128);
  await terminalShot(browser, 'agent-git', 'claude-sre@agent-sandbox: ~/src', gitTranscript.slice(0, -1));

  // claude-sre with gh through hallpass-api: a read through the auto-approved profile, a comment that needs approval
  // (the proxy files the request with the command, hallpass-api waits and runs it again), and a call no profile allows.
  const sshWrapper = join(gitHome, 'ssh');
  writeFileSync(sshWrapper, `#!/bin/sh\nexec ssh -F ${sshConfig} "$@"\n`, { mode: 0o755 });
  const apiTranscript: string[] = [];
  const hallpassApi = async (shown: string, args: string[], want = 0, during?: () => Promise<void>) => {
    const run = runTool(
      HALLPASS_API,
      ['--gateway', 'center', '--ssh', sshWrapper, ...args],
      gitHome,
      agentToolEnv(gitHome),
    );
    if (during) {
      // If hallpass-api ends first, it never filed the request: show what it printed instead of a polling timeout.
      await Promise.race([
        during(),
        run.then((r) => {
          throw new Error(`hallpass-api ended before approval: exit ${String(r.code)}\n${r.out}`);
        }),
      ]);
    }
    const res = await run;
    if (res.code !== want) {
      throw new Error(`hallpass-api ${args.join(' ')}: exit ${String(res.code)}\n${res.out}`);
    }
    apiTranscript.push(`$ ${shown}`, ...(res.out ? outputLines(res.out) : []));
    if (res.code !== 0) {
      apiTranscript.push(`[exit ${String(res.code)}]`);
    }
    apiTranscript.push('');
  };
  const issueList = '.[] | "#\\(.number) \\(.title)"';
  await hallpassApi(`hallpass-api --gateway center -- gh api repos/acme/shop/issues --jq '${issueList}'`, [
    '--',
    'gh',
    'api',
    'repos/acme/shop/issues',
    '--jq',
    issueList,
  ]);
  // --silent: on a refusal gh would also print the proxy's JSON error body after its one-line message.
  const rca = 'Root cause: 10s upstream timeout. Fix: agent/cart-timeout';
  await hallpassApi(
    `hallpass-api --gateway center --reason 'Post the root cause on #412' -- gh api repos/acme/shop/issues/412/comments -f body='${rca}' --silent`,
    [
      '--reason',
      'Post the root cause on #412',
      '--',
      'gh',
      'api',
      'repos/acme/shop/issues/412/comments',
      '-f',
      `body=${rca}`,
      '--silent',
    ],
    0,
    async () => {
      await api.call('POST', `/api/v1/requests/${(await pending('claude-sre', 'github')).id}/approve`, {
        duration: HOUR,
        comment: 'Comment only.',
      });
    },
  );
  await hallpassApi(
    'hallpass-api --gateway center -- gh api -X DELETE repos/acme/shop --silent',
    ['--', 'gh', 'api', '-X', 'DELETE', 'repos/acme/shop', '--silent'],
    1,
  );
  await terminalShot(browser, 'agent-api', 'claude-sre@agent-sandbox: ~/src', apiTranscript.slice(0, -1));

  // claude-sre copies a build artifact with scp and checks it with sftp through the file-transfer role.
  const artifact = join(gitHome, 'cart-1.4.4.tar.gz');
  writeFileSync(artifact, randomBytes(96 * 1024));
  const sshTool = async (file: string, args: string[]) => {
    const res = await runTool(file, ['-F', sshConfig, ...args], gitHome, process.env);
    if (res.code !== 0) {
      throw new Error(`${file} ${args.join(' ')}: exit ${String(res.code)}\n${res.out}`);
    }
  };
  await sshTool('scp', ['-q', artifact, 'web1+files@center:/srv/app/incoming/']);
  const batch = join(gitHome, 'sftp.batch');
  writeFileSync(
    batch,
    [
      'ls -l /srv/app/incoming',
      'get /srv/app/incoming/cart-1.4.4.tar.gz verify.tar.gz',
      'rename /srv/app/incoming/cart-1.4.4.tar.gz /srv/app/incoming/cart-1.4.4.ready.tar.gz',
      '',
    ].join('\n'),
  );
  await sshTool('sftp', ['-q', '-b', batch, 'web1+files@center']);

  // deploy-bot: one denied, one canceled, one left pending.
  await ssh(bot, ['request', 'web1', '--role', 'deploy', "--reason='Hotfix straight to production'"]);
  await api.call('POST', `/api/v1/requests/${(await pending('deploy-bot', 'web1')).id}/deny`, {
    comment: 'Needs a change ticket.',
  });
  await ssh(bot, ['request', 'web1', '--role', 'deploy', "--reason='Rollback rehearsal'"]);
  await ssh(bot, ['cancel', (await pending('deploy-bot', 'web1')).id]);
  await ssh(bot, [
    'request',
    'web1',
    '--role',
    'deploy',
    '--duration',
    '1h',
    "--reason='Ship release 1.4.4 (OPS-2297): cart timeout fix'",
  ]);
  const open = await pending('deploy-bot', 'web1');

  // A live shell for the dashboard and activity pages.
  const live = new Pty(sre, knownHosts, ['connect', 'db1', '--role', 'maintenance']);
  await live.run('tail -3 /var/log/postgresql/postgresql-16-main.log');
  await live.prompt();

  // ---- Console pages ----------------------------------------------------------------------------------------------
  await page.goto('/');
  await expect(page.getByText('Live activities (1)')).toBeVisible();
  await themed(page, 'dashboard');
  await page.goto('/activities');
  await shot(page, 'activities');
  await page.goto('/sessions');
  await themed(page, 'sessions');
  await page.goto('/requests');
  await themed(page, 'requests');
  await page.goto(`/requests/${open.id}`);
  await themed(page, 'request-pending');
  await themed(page, 'request-approve', async () => {
    if (!(await page.getByRole('dialog', { name: 'Approve access request' }).isVisible())) {
      await page.getByRole('button', { name: 'Approve', exact: true }).click();
    }
    await expect(page.getByRole('dialog', { name: 'Approve access request' })).toBeVisible();
  });
  await page.keyboard.press('Escape');

  await live.run('exit');
  await live.done;

  const sessions = await api.call<{ items: AccessSession[] }>('GET', '/api/v1/access-sessions');
  const web1Session = sessions.items.find(
    (s) => s.agent_id === agents['claude-sre'] && s.role_id === roleIds['web1/inspect'],
  );
  if (!web1Session) {
    throw new Error('no web1 session');
  }
  await page.goto(`/sessions/${web1Session.id}`);
  await themed(page, 'session-overview');
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await cardShot(
      page,
      page
        .locator('.ant-card')
        .filter({ has: page.getByText('Timeline', { exact: true }) })
        .last(),
      `session-timeline-${scheme}`,
    );
  }
  await page.emulateMedia({ colorScheme: 'light' });
  const replay = page
    .locator('.ant-card')
    .filter({ has: page.getByText('Replay', { exact: true }) })
    .first();
  await replay.scrollIntoViewIfNeeded();
  await pickOption(page, replay.getByRole('combobox', { name: 'Channel to replay' }), 'shell (PTY)');
  await replay.getByRole('button', { name: 'Load recording' }).click();
  await pickOption(page, replay.getByRole('combobox', { name: 'Playback speed' }), '8×');
  await replay.getByRole('button', { name: 'Play' }).click();
  await expect(replay.getByRole('button', { name: 'Replay' })).toBeVisible({ timeout: 60_000 });
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await cardShot(page, replay, `session-replay-${scheme}`);
  }
  await page.emulateMedia({ colorScheme: 'light' });

  await page.goto('/agents');
  await shot(page, 'agents');
  await page.goto(`/agents/${agents['claude-sre'] ?? ''}`);
  await shot(page, 'agent');
  await page.goto('/servers');
  await shot(page, 'servers');
  await page.goto(`/servers/${servers.web1 ?? ''}`);
  await shot(page, 'server');
  await page.goto('/git');
  await themed(page, 'git-remotes');
  await page.goto(`/git/${forge}`);
  await expect(page.getByText('acme-push').first()).toBeVisible();
  await themed(page, 'git-remote');
  const gitSession = sessions.items.find((s) => s.role_id === roleIds['forge/acme-push']);
  if (!gitSession) {
    throw new Error('no git push session');
  }
  await page.goto(`/sessions/${gitSession.id}`);
  for (const scheme of ['light', 'dark'] as const) {
    await page.emulateMedia({ colorScheme: scheme });
    await cardShot(
      page,
      page
        .locator('.ant-card')
        .filter({ has: page.getByText('Timeline', { exact: true }) })
        .last(),
      `git-timeline-${scheme}`,
    );
  }
  await page.emulateMedia({ colorScheme: 'light' });

  // API target, the request hallpass-api filed (with the reported command) and the recorded API calls; the file
  // transfer session's operations.
  await page.goto('/apis');
  await themed(page, 'apis');
  await page.goto(`/apis/${github}`);
  await expect(page.getByText('acme-issues').first()).toBeVisible();
  await themed(page, 'api-target');
  const approved = await api.call<{ items: AccessRequest[] }>('GET', '/api/v1/requests?state=approved');
  const apiRequest = approved.items.find((r) => r.role_id === roleIds['github/acme-issues']);
  if (!apiRequest) {
    throw new Error('no API request');
  }
  await page.goto(`/requests/${apiRequest.id}`);
  await themed(page, 'api-request');
  for (const [role, name] of [
    ['github/acme-issues', 'api-timeline'],
    ['web1/files', 'file-timeline'],
  ] as const) {
    const s = sessions.items.find((x) => x.role_id === roleIds[role]);
    if (!s) {
      throw new Error(`no ${role} session`);
    }
    await page.goto(`/sessions/${s.id}`);
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme });
      await cardShot(
        page,
        page
          .locator('.ant-card')
          .filter({ has: page.getByText('Timeline', { exact: true }) })
          .last(),
        `${name}-${scheme}`,
      );
    }
    await page.emulateMedia({ colorScheme: 'light' });
  }

  await page.goto('/policy');
  await themed(page, 'policy');
  await page.getByRole('tab', { name: 'Effective access' }).click();
  await pickOption(page, page.getByRole('combobox', { name: 'Agent' }), 'claude-sre');
  await expect(page.getByRole('columnheader', { name: 'Deciding rules' })).toBeVisible();
  await themed(page, 'policy-effective');
  await page.goto('/audit');
  await shot(page, 'audit');
  await page.goto('/settings/system');
  await shot(page, 'system');
  await page.goto('/settings/integrations');
  await page.getByRole('button', { name: 'New integration' }).click();
  await page.getByRole('form', { name: 'Chat integration' }).getByLabel('Name').fill('ops-approvals');
  await shot(page, 'integration-new');
  await page.keyboard.press('Escape');

  // ---- Operators, automation tokens, backups and a web terminal ---------------------------------------------------
  for (const o of [
    { email: 'grace@example.com', display_name: 'Grace Hopper', roles: ['approver'] },
    { email: 'alan@example.com', display_name: 'Alan Turing', roles: ['auditor'] },
  ]) {
    await api.call('POST', '/api/v1/operators', o);
  }
  await page.goto('/operators');
  await shot(page, 'operators');
  await api.call('POST', '/api/v1/api-tokens', {
    name: 'terraform',
    role: 'administrator',
    never_expires: true,
  });
  await api.call('POST', '/api/v1/api-tokens', {
    name: 'grafana-audit',
    role: 'auditor',
    expires_in_days: 90,
  });
  await page.goto('/settings/api-tokens');
  await shot(page, 'api-tokens');

  await api.call('PUT', '/api/v1/system/backups/target', {
    enabled: true,
    endpoint: 'https://s3.example.com',
    region: 'us-east-1',
    bucket: 'hallpass-backups',
    prefix: 'hallpass/',
    path_style: true,
    access_key_id: process.env.HP_DOCS_S3_ACCESS_KEY ?? '',
    secret_access_key: process.env.HP_DOCS_S3_SECRET_KEY ?? '',
    ca_bundle_pem: readFileSync(DOCS_CA, 'utf8'),
    allow_private_network: true,
    interval: '6h',
    keep_last: 28,
    keep_daily_days: 30,
  });
  await api.call('POST', '/api/v1/system/backups/runs', {});
  await expect
    .poll(
      async () =>
        (await api.call<{ items: { state: string }[] }>('GET', '/api/v1/system/backups/runs')).items[0]
          ?.state,
      { timeout: 60_000 },
    )
    .toBe('succeeded');
  await page.goto('/settings/backups');
  await shot(page, 'backups');

  await page.goto(`/servers/${servers.web1 ?? ''}`);
  await page.getByRole('tab', { name: 'Roles' }).click();
  await page.getByRole('button', { name: 'Open a terminal as inspect' }).click();
  const terminal = page.getByRole('dialog');
  await expect(terminal.locator('.xterm-rows')).toContainText('$', { timeout: 30_000 });
  for (const line of ['uptime', 'tail -2 /var/log/nginx/error.log']) {
    await page.keyboard.type(line);
    await page.keyboard.press('Enter');
    await sleep(700);
  }
  await shot(page, 'web-terminal');
  await page.keyboard.press('Escape');
});
