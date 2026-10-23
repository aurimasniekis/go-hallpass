import { CheckCircleFilled } from '@ant-design/icons';
import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Card, Radio, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../../api/client';
import { errorMessage } from '../../../api/errors';
import { qk } from '../../../api/queryKeys';
import type { LoginCredential, Role } from '../../../api/types';
import { CodeBlock } from '../../../ds/CodeBlock';
import { ConfirmAction } from '../../../ds/ConfirmAction';
import { CopyField } from '../../../ds/CopyField';
import { Fingerprint } from '../../../ds/Fingerprint';
import { StatusBadge } from '../../../ds/StatusBadge';
import { revealControls } from '../../../ds/untrusted';
import { formatDateTime } from '../../../lib/format';
import { useNow } from '../../../lib/useNow';
import { CertBindingPanel } from '../../credentials/CertBindingPanel';
import { credentialActions } from '../../credentials/credentialActions';
import { focusCredential, installCommand, prepareSshDirCommand, type RoleLogin } from './model';

const LOGIN_BADGE: Record<RoleLogin, { tone: 'success' | 'warning' | 'neutral' | 'info'; label: string }> = {
  active: { tone: 'success', label: 'Login ready' },
  certificate: { tone: 'success', label: 'Certificate login bound' },
  pending: { tone: 'warning', label: 'Key not active yet' },
  none: { tone: 'neutral', label: 'No login credential' },
  unknown: { tone: 'neutral', label: 'Unknown' },
};

/** Probe ("Test login") with an explicit result and retry. The result is stored on the credential. */
function TestLogin({ cred, roleId }: { cred: LoginCredential; roleId: string }) {
  const queryClient = useQueryClient();
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const probe = async () => {
    setPending(true);
    setError(null);
    try {
      await api.call('post', '/api/v1/credentials/{id}/probe', { path: { id: cred.id } });
      await queryClient.invalidateQueries({ queryKey: qk.credentials(roleId) });
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };
  const tested = Boolean(cred.probe_ok_at) || Boolean(cred.probe_error);
  return (
    <Space orientation="vertical" size={8} style={{ width: '100%' }}>
      <div>
        <Button onClick={() => void probe()} loading={pending} type={tested ? 'default' : 'primary'}>
          {tested ? 'Test login again' : 'Test login'}
        </Button>
      </div>
      {error !== null ? (
        <Alert type="error" showIcon title="The test could not run" description={errorMessage(error)} />
      ) : cred.probe_error ? (
        <Alert
          type="error"
          showIcon
          title="The destination did not accept the key"
          description={
            <>
              <div className="hp-mono">{revealControls(cred.probe_error)}</div>
              <div style={{ marginTop: 4 }}>
                Check that the line is in <code className="hp-mono">authorized_keys</code> of the remote user,
                that the file and <code className="hp-mono">~/.ssh</code> are not group- or world-writable,
                and that the <code className="hp-mono">from=</code> addresses match the gateway&apos;s egress
                address. Then test again.
              </div>
            </>
          }
        />
      ) : cred.probe_ok_at ? (
        <Alert
          type="success"
          showIcon
          title={`Login works: the destination accepted the key (${formatDateTime(cred.probe_ok_at)})`}
        />
      ) : null}
    </Space>
  );
}

/** Credential step for one role: generate (or bind a certificate) → install → test → activate. */
export function RoleLoginSetup({
  role,
  credentials,
  login,
  canManage,
  onCertificateBound,
}: {
  role: Role;
  credentials: LoginCredential[] | undefined;
  login: RoleLogin;
  canManage: boolean;
  onCertificateBound: () => void;
}) {
  const queryClient = useQueryClient();
  const now = useNow(30_000);
  const [mode, setMode] = useState<'key' | 'certificate'>('key');
  const refresh = () => queryClient.invalidateQueries({ queryKey: qk.credentials(role.id) });
  const focus = focusCredential(credentials);
  const active = credentials?.find((c) => c.state === 'active');
  const badge = LOGIN_BADGE[login];

  return (
    <Card
      size="small"
      title={
        <span>
          Role <strong>{role.alias}</strong> logs in as <code className="hp-mono">{role.remote_user}</code>
        </span>
      }
      extra={<StatusBadge tone={badge.tone}>{badge.label}</StatusBadge>}
    >
      {!canManage ? (
        <Alert
          type="info"
          showIcon
          title="Login credentials need the credentials.manage permission"
          description="Ask an administrator to finish this step."
        />
      ) : login === 'active' && active ? (
        <Space align="start">
          <CheckCircleFilled className="hp-ok-icon" aria-hidden="true" />
          <div>
            The gateway logs in with the active key <Fingerprint value={active.fingerprint} />
            {active.activated_at ? ` (activated ${formatDateTime(active.activated_at)})` : ''}.
          </div>
        </Space>
      ) : login === 'certificate' ? (
        <Space align="start">
          <CheckCircleFilled className="hp-ok-icon" aria-hidden="true" />
          <div>
            The certificate binding was saved. The API does not report bindings, so after a reload this role
            shows as not configured; that is expected.
          </div>
        </Space>
      ) : (
        <Space orientation="vertical" size={12} style={{ width: '100%' }}>
          <Radio.Group
            value={mode}
            onChange={(e) => {
              setMode(e.target.value as 'key' | 'certificate');
            }}
            optionType="button"
            options={[
              { value: 'key', label: 'Login key (recommended)' },
              { value: 'certificate', label: 'Certificate (user CA)' },
            ]}
          />
          {mode === 'certificate' ? (
            <CertBindingPanel roleId={role.id} remoteUser={role.remote_user} onBound={onCertificateBound} />
          ) : !focus ? (
            <div>
              <p className="hp-card-intro">
                Hallpass generates a key pair and keeps the private key encrypted; you install only the public
                line on the destination.
              </p>
              <ConfirmAction<LoginCredential>
                label="Generate login key"
                danger={false}
                title={`Generate a login key for ${role.alias}`}
                confirmLabel="Generate"
                buttonProps={{ type: 'primary' }}
                description="The key starts as pending: install its authorized_keys line on the destination, test the login, then activate it. Generating needs recent authentication."
                onConfirm={({ idempotencyKey }) =>
                  api.call('post', '/api/v1/roles/{id}/credentials:generate', {
                    path: { id: role.id },
                    idempotencyKey,
                  })
                }
                onSuccess={() => void refresh()}
              />
            </div>
          ) : (
            <ol className="hp-steps">
              <li>
                <strong>Install the key on the destination.</strong> Run this on the server as an
                administrator:
                <CodeBlock code={installCommand(focus.authorized_keys_line, role.remote_user)} />
                <span className="hp-legend">
                  If <code className="hp-mono">~{role.remote_user}/.ssh</code> does not exist yet, create it
                  first:
                </span>
                <CodeBlock code={prepareSshDirCommand(role.remote_user)} />
                <CopyField label="authorized_keys line" value={focus.authorized_keys_line} />
                <p className="hp-legend" style={{ marginTop: 4 }}>
                  The <code className="hp-mono">from=</code> and <code className="hp-mono">restrict</code>{' '}
                  options limit the key to the gateway. Fingerprint <Fingerprint value={focus.fingerprint} />
                </p>
              </li>
              <li>
                <strong>Test the login.</strong> The gateway connects to the destination with this key.
                <div style={{ marginTop: 8 }}>
                  <TestLogin cred={focus} roleId={role.id} />
                </div>
              </li>
              <li>
                <strong>Activate.</strong> New connections for this role use the key.
                <div style={{ marginTop: 8 }}>
                  <ConfirmAction<LoginCredential>
                    label="Activate"
                    danger={false}
                    title={`Activate the login key for ${role.alias}`}
                    confirmLabel="Activate"
                    disabled={!credentialActions(focus, now).activate}
                    buttonProps={{ type: 'primary' }}
                    description="New connections for this role will use this key. Activation needs recent authentication."
                    onConfirm={() =>
                      api.call('post', '/api/v1/credentials/{id}/activate', { path: { id: focus.id } })
                    }
                    onSuccess={() => void refresh()}
                  />
                  {!credentialActions(focus, now).activate ? (
                    <span className="hp-legend" style={{ marginLeft: 8 }}>
                      Available after a successful test.
                    </span>
                  ) : null}
                </div>
              </li>
            </ol>
          )}
        </Space>
      )}
    </Card>
  );
}
