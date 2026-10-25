import { useQuery } from '@tanstack/react-query';
import { Card, Space, Typography } from 'antd';

import { gatewayHostKeysQueryOptions } from '../../api/queries';
import { CodeBlock } from '../../ds/CodeBlock';
import { ErrorState, LoadingState } from '../../ds/states';

/** The alias the docs use for the gateway in ~/.ssh/config. */
const ALIAS = 'center';

/** `host` for port 22, `[host]:port` otherwise (OpenSSH known_hosts syntax). */
export function knownHostsName(host: string, port: number): string {
  return port === 22 ? host : `[${host}]:${String(port)}`;
}

/** The ~/.ssh/config block for the gateway. */
export function sshConfigBlock(host: string, port: number, keyFile: string): string {
  return [
    `Host ${ALIAS}`,
    `  HostName ${host}`,
    `  Port ${String(port)}`,
    '  User agent                  # any value works for commands; scp and sftp put the server here instead',
    `  IdentityFile ${keyFile}`,
    '  IdentitiesOnly yes',
    '  StrictHostKeyChecking yes',
    '  ForwardAgent no',
    '  ClearAllForwardings yes',
    '  ServerAliveInterval 30',
  ].join('\n');
}

/**
 * How to set up the machine an agent runs on: generate its key, pin the gateway host key, and point SSH at the gateway.
 * The address is where agents connect (`ssh.public_address`, or the public URL host with the SSH port).
 */
export function AgentConnect({ agentName }: { agentName: string }) {
  const gw = useQuery(gatewayHostKeysQueryOptions());
  const keyFile = `~/.ssh/${agentName}_ed25519`;
  return (
    <Card size="small" title="Set up the agent's machine">
      {gw.isPending ? (
        <LoadingState />
      ) : gw.isError ? (
        <ErrorState error={gw.error} onRetry={() => void gw.refetch()} />
      ) : (
        <Space orientation="vertical" size={12} style={{ width: '100%' }}>
          <div>
            <Typography.Text strong>1. Create the agent&apos;s key</Typography.Text> on the machine, container
            or VM where it runs, then add the public key under <strong>Keys</strong>. The private key never
            leaves that machine.
            <CodeBlock
              code={`ssh-keygen -t ed25519 -N "" -C ${agentName} -f ${keyFile}\ncat ${keyFile}.pub`}
            />
          </div>
          <div>
            <Typography.Text strong>2. Pin the gateway&apos;s host key</Typography.Text> in{' '}
            <code className="hp-mono">~/.ssh/known_hosts</code>, so the agent never accepts another key:
            <CodeBlock
              label="known_hosts lines"
              code={
                gw.data.items
                  .filter((k) => k.state === 'active')
                  .map((k) => `${knownHostsName(gw.data.ssh_host, gw.data.ssh_port)} ${k.public_key}`)
                  .join('\n') || '# no active gateway host key'
              }
            />
          </div>
          <div>
            <Typography.Text strong>3. Add the gateway</Typography.Text> to{' '}
            <code className="hp-mono">~/.ssh/config</code>:
            <CodeBlock
              label="SSH config"
              code={sshConfigBlock(gw.data.ssh_host, gw.data.ssh_port, keyFile)}
            />
          </div>
          <div>
            <Typography.Text strong>4. Try it</Typography.Text>: the agent lists what it can request.
            <CodeBlock code={`ssh ${ALIAS} list`} />
          </div>
        </Space>
      )}
    </Card>
  );
}
