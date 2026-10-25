import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { mockApi } from '../policy/mockApi';
import { renderInRouter } from '../requests/testHelpers';
import { AgentConnect, knownHostsName, sshConfigBlock } from './AgentConnect';

describe('<AgentConnect>', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('shows the key command, pinned host keys and the SSH config for the gateway address', async () => {
    mockApi({
      'GET /api/v1/system/gateway-host-keys': {
        ssh_host: 'ssh.example.com',
        ssh_port: 2222,
        items: [
          {
            id: 'ghk_1',
            algorithm: 'ssh-ed25519',
            public_key: 'ssh-ed25519 AAAAC3active',
            fingerprint: 'SHA256:a',
            state: 'active',
            created_at: '2026-10-25T08:00:00Z',
          },
          {
            id: 'ghk_2',
            algorithm: 'ssh-ed25519',
            public_key: 'ssh-ed25519 AAAAC3retired',
            fingerprint: 'SHA256:b',
            state: 'retired',
            created_at: '2026-10-25T08:00:00Z',
          },
        ],
      },
    });
    renderInRouter(<AgentConnect agentName="sre-bot" />);
    expect(
      await screen.findByText(/ssh-keygen -t ed25519 -N "" -C sre-bot -f ~\/\.ssh\/sre-bot_ed25519/),
    ).toBeInTheDocument();
    expect(screen.getByText('[ssh.example.com]:2222 ssh-ed25519 AAAAC3active')).toBeInTheDocument();
    expect(screen.queryByText(/AAAAC3retired/)).not.toBeInTheDocument();
    expect(screen.getByText(/HostName ssh\.example\.com/)).toBeInTheDocument();
    expect(screen.getByText('ssh center list')).toBeInTheDocument();
  });

  it('formats known_hosts names and the config block', () => {
    expect(knownHostsName('ssh.example.com', 22)).toBe('ssh.example.com');
    expect(knownHostsName('ssh.example.com', 2222)).toBe('[ssh.example.com]:2222');
    const block = sshConfigBlock('ssh.example.com', 22, '~/.ssh/a_ed25519');
    expect(block).toContain('Host center\n  HostName ssh.example.com\n  Port 22\n');
    expect(block).toContain('IdentityFile ~/.ssh/a_ed25519');
    expect(block).toContain('StrictHostKeyChecking yes');
  });
});
