import { Collapse } from 'antd';
import type { ReactNode } from 'react';

import { CodeBlock } from '../../ds/CodeBlock';
import { isPlainUserName, shellQuote } from '../../lib/shell';

function Tip({ title = 'How to set this up', children }: { title?: string; children: ReactNode }) {
  return <Collapse size="small" className="hp-tip" items={[{ key: 'tip', label: title, children }]} />;
}

/** Host-name principals to sign into a host certificate: the server's alias and address. */
function hostPrincipals(names: readonly string[]): string {
  const clean = names.map((n) => n.trim()).filter((n) => /^[A-Za-z0-9_.:-]+$/.test(n));
  return clean.length > 0 ? clean.join(',') : 'web1.example.com,10.0.0.5';
}

/**
 * Exact commands for trusting host certificates instead of pinning each host key (PLAN §11.2). The
 * private CA key never touches HallPass: only `host_ca.pub` is pasted.
 */
export function HostCASetupTip({
  alias,
  principals = [],
}: {
  alias?: string;
  principals?: readonly string[];
}) {
  const id = alias && /^[A-Za-z0-9_.-]+$/.test(alias) ? alias : 'web1';
  const names = hostPrincipals(principals);
  return (
    <Tip>
      <ol className="hp-steps">
        <li>
          Create a host CA on an offline or well-protected machine (keep{' '}
          <code className="hp-mono">host_ca</code> private):
          <CodeBlock code="ssh-keygen -t ed25519 -f host_ca -C hallpass-host-ca" />
        </li>
        <li>
          Sign the destination&apos;s host key. <code className="hp-mono">-n</code> lists the names the
          certificate is valid for; bind the same principals in HallPass:
          <CodeBlock
            code={`ssh-keygen -s host_ca -I ${id} -h -n ${names} -V +52w /etc/ssh/ssh_host_ed25519_key.pub`}
          />
        </li>
        <li>
          On the destination, present the certificate and reload sshd:
          <CodeBlock
            label="Configuration"
            code={`echo 'HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub' | sudo tee -a /etc/ssh/sshd_config
sudo sshd -t && sudo systemctl reload sshd   # the unit is "ssh" on Debian/Ubuntu`}
          />
        </li>
        <li>
          Paste the contents of <code className="hp-mono">host_ca.pub</code> here, then use{' '}
          <strong>Bind CA</strong> on the server with its principals (for example{' '}
          <code className="hp-mono">{names}</code>).
        </li>
      </ol>
    </Tip>
  );
}

/**
 * Exact commands for certificate logins to a destination (PLAN §11.3): the destination trusts the
 * HallPass user CA and maps principals to the login user.
 */
export function UserCASetupTip({
  caPublicKey,
  remoteUser,
  principals = [],
}: {
  caPublicKey?: string;
  remoteUser?: string;
  principals?: readonly string[];
}) {
  const user = remoteUser && isPlainUserName(remoteUser) ? remoteUser : 'deploy';
  const principalList = principals.length > 0 ? principals : [user];
  const caLine = caPublicKey ? shellQuote(caPublicKey.trim()) : "'<user CA public key>'";
  return (
    <Tip title="How to set up the destination for certificate logins">
      <ol className="hp-steps">
        <li>
          Install the HallPass user CA public key on the destination
          {caPublicKey ? '' : ' (copy it from "Public key" in User certificate authorities)'}:
          <CodeBlock code={`echo ${caLine} | sudo tee /etc/ssh/hallpass_user_ca.pub`} />
        </li>
        <li>
          Trust it in <code className="hp-mono">/etc/ssh/sshd_config</code> and read principals per user:
          <CodeBlock
            label="Configuration"
            code={`TrustedUserCAKeys /etc/ssh/hallpass_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u`}
          />
        </li>
        <li>
          Allow the principal(s) to log in as <code className="hp-mono">{user}</code>:
          <CodeBlock
            code={`sudo mkdir -p /etc/ssh/principals
printf '%s\\n' ${principalList.map(shellQuote).join(' ')} | sudo tee /etc/ssh/principals/${user}`}
          />
        </li>
        <li>
          Reload sshd:
          <CodeBlock
            code={'sudo sshd -t && sudo systemctl reload sshd   # the unit is "ssh" on Debian/Ubuntu'}
          />
        </li>
        <li>
          Bind the CA to the role with the same principal(s) using <strong>Bind user CA</strong>.
        </li>
      </ol>
    </Tip>
  );
}
