import { execFile } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

import type { APIRequestContext } from '@playwright/test';

import { stateFile } from './env';

/** Gateway SSH address for agent-side steps, e.g. `127.0.0.1:18422`. Agent flows skip when unset. */
export const sshAddr = process.env.HALLPASS_E2E_SSH;

export interface AgentKey {
  privatePath: string;
  publicKey: string;
}

/** Generates an ed25519 agent key at test time (never committed). */
export async function generateAgentKey(name: string): Promise<AgentKey> {
  const privatePath = stateFile(`${name}_ed25519`);
  for (const p of [privatePath, `${privatePath}.pub`]) {
    if (existsSync(p)) {
      rmSync(p);
    }
  }
  await run('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-C', `${name}@e2e`, '-f', privatePath]);
  return { privatePath, publicKey: readFileSync(`${privatePath}.pub`, 'utf8').trim() };
}

/** Pins the gateway host keys from the API in a known_hosts file (no trust-on-first-use). */
export async function writeKnownHosts(request: APIRequestContext): Promise<string> {
  if (!sshAddr) {
    throw new Error('HALLPASS_E2E_SSH is not set');
  }
  const [host, port] = sshAddr.split(':');
  const res = await request.get('/api/v1/system/gateway-host-keys');
  const body = (await res.json()) as { items: { public_key: string; state: string }[] };
  const lines = body.items.map((k) => `[${host ?? '127.0.0.1'}]:${port ?? '22'} ${k.public_key}`);
  const path = stateFile('known_hosts');
  writeFileSync(path, `${lines.join('\n')}\n`);
  return path;
}

export interface SshResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs one gateway command as the agent (`ssh … agent@gateway <words>`). */
export function gatewaySsh(key: AgentKey, knownHosts: string, words: string[]): Promise<SshResult> {
  const [host, port] = (sshAddr ?? '').split(':');
  return run('ssh', [
    // Ignore the developer's ~/.ssh/config (forwardings, identities) for a reproducible client.
    '-F',
    '/dev/null',
    '-T',
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
    '-o',
    'ConnectTimeout=10',
    `agent@${host ?? '127.0.0.1'}`,
    ...words,
  ]);
}

function run(cmd: string, args: string[]): Promise<SshResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: 60_000 }, (error, stdout, stderr) => {
      const code =
        error && typeof (error as { code?: unknown }).code === 'number'
          ? (error as { code: number }).code
          : error
            ? 1
            : 0;
      resolve({ code, stdout, stderr });
    });
  });
}
