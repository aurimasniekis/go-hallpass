import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Button, Card, Form, Input, Space, Table } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { credentialsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { LoginCredential } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { CopyField } from '../../ds/CopyField';
import { Fingerprint } from '../../ds/Fingerprint';
import { EmptyState, ErrorState, LoadingState } from '../../ds/states';
import { revealControls } from '../../ds/untrusted';
import { formatDateTime } from '../../lib/format';
import { useNow } from '../../lib/useNow';
import { StateBadge } from '../../shared/StateBadge';
import { FormModal } from '../servers/FormModal';
import { credentialActions, credentialNextStep } from './credentialActions';

function ProbeButton({ cred, roleId }: { cred: LoginCredential; roleId: string }) {
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const [pending, setPending] = useState(false);
  const probe = async () => {
    setPending(true);
    try {
      const res = await api.call('post', '/api/v1/credentials/{id}/probe', { path: { id: cred.id } });
      await queryClient.invalidateQueries({ queryKey: qk.credentials(roleId) });
      if (res.probe_error) {
        void message.error(`Probe failed: ${revealControls(res.probe_error)}`);
      } else {
        void message.success('Probe succeeded: the destination accepted this key.');
      }
    } catch (e) {
      void message.error(`Probe could not run: ${errorMessage(e)}`);
    } finally {
      setPending(false);
    }
  };
  return (
    <Button size="small" loading={pending} onClick={() => void probe()}>
      Probe
    </Button>
  );
}

function ActivateButton({ cred, roleId, force }: { cred: LoginCredential; roleId: string; force: boolean }) {
  const queryClient = useQueryClient();
  return (
    <ConfirmAction
      label={force ? 'Force activate' : 'Activate'}
      danger={force}
      title={force ? 'Force activation without a successful probe' : 'Activate credential'}
      confirmLabel={force ? 'Force activate' : 'Activate'}
      typedConfirmation={force ? 'FORCE' : undefined}
      buttonProps={{ size: 'small', type: force ? 'default' : 'primary' }}
      description={
        force ? (
          <Alert
            type="warning"
            showIcon
            title="The destination has not accepted this key"
            description="The last probe failed. If the key is not installed, every new connection with this role will fail once it becomes active. The forced activation is recorded in the audit log."
          />
        ) : (
          <p>
            New connections will use this key. The currently active key moves to <em>retiring</em> and keeps
            working for the overlap window, then remove its authorized_keys line and retire it.
          </p>
        )
      }
      onConfirm={() =>
        api.call('post', '/api/v1/credentials/{id}/activate', {
          path: { id: cred.id },
          ...(force ? { query: { force: true } } : {}),
        })
      }
      onSuccess={() => void queryClient.invalidateQueries({ queryKey: qk.credentials(roleId) })}
    />
  );
}

function RevokeButton({ cred, roleId }: { cred: LoginCredential; roleId: string }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState('');
  return (
    <ConfirmAction
      label="Revoke"
      title="Revoke credential"
      confirmLabel="Revoke"
      typedConfirmation="REVOKE"
      buttonProps={{ size: 'small' }}
      onOpen={() => {
        setReason('');
      }}
      description={
        <>
          <p>
            HallPass stops using this key immediately. If it is the active key, connections for this role fail
            until another credential is activated. Also remove its authorized_keys line from the destination.
          </p>
          <Fingerprint value={cred.fingerprint} />
          <label htmlFor={`cred-revoke-${cred.id}`} style={{ display: 'block', marginTop: 8 }}>
            Reason (recorded in the audit log)
          </label>
          <Input
            id={`cred-revoke-${cred.id}`}
            value={reason}
            maxLength={1000}
            onChange={(e) => {
              setReason(e.target.value);
            }}
          />
        </>
      }
      onConfirm={({ idempotencyKey }) =>
        api.call('post', '/api/v1/credentials/{id}/revoke', {
          path: { id: cred.id },
          body: reason.trim() ? { reason: reason.trim() } : {},
          idempotencyKey,
        })
      }
      onSuccess={() => void queryClient.invalidateQueries({ queryKey: qk.credentials(roleId) })}
    />
  );
}

/**
 * Destination login credentials of a role (PLAN §11.3, HP-KEY-*). Procedure (PLAN §18.4/§18.11):
 * generate (or import) → install the authorized_keys line on the destination → probe → activate → after
 * the overlap remove the old line → retire/revoke the old key. Private keys never leave the server; an
 * imported PEM is sent once and dropped from the form.
 */
export function CredentialsPanel({ roleId }: { roleId: string }) {
  const queryClient = useQueryClient();
  const query = useQuery(credentialsQueryOptions(roleId));
  const now = useNow(30_000);
  const [importing, setImporting] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);

  const refresh = () => queryClient.invalidateQueries({ queryKey: qk.credentials(roleId) });
  const items = query.data?.items ?? [];
  const focus = items.find((c) => c.id === selected) ?? items.find((c) => c.state === 'pending') ?? null;

  return (
    <Card
      size="small"
      title="Login credentials"
      extra={
        <Space>
          <ConfirmAction
            label="Generate key"
            danger={false}
            title="Generate a new login key"
            confirmLabel="Generate"
            buttonProps={{ size: 'small', type: 'primary' }}
            description="HallPass creates a new key pair and keeps the private key encrypted. The key starts as pending: install its authorized_keys line on the destination, probe, then activate."
            onConfirm={({ idempotencyKey }) =>
              api.call('post', '/api/v1/roles/{id}/credentials:generate', {
                path: { id: roleId },
                idempotencyKey,
              })
            }
            onSuccess={(cred) => {
              setSelected(cred.id);
              void refresh();
            }}
          />
          <Button
            size="small"
            onClick={() => {
              setImporting(true);
            }}
          >
            Import key
          </Button>
        </Space>
      }
    >
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <ol aria-label="Rotation procedure" style={{ margin: 0, paddingInlineStart: 20 }}>
          <li>Generate or import a key</li>
          <li>Install its authorized_keys line on the destination</li>
          <li>Probe</li>
          <li>Activate</li>
          <li>After the overlap, remove the old line and retire the old key</li>
        </ol>
        {query.isPending ? (
          <LoadingState />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : items.length === 0 ? (
          <EmptyState
            title="No login credentials"
            description="Without an active credential (or a certificate binding) the gateway cannot log in to the destination."
          />
        ) : (
          <>
            <Table<LoginCredential>
              size="small"
              pagination={false}
              rowKey="id"
              dataSource={items}
              scroll={{ x: 'max-content' }}
              aria-label="Login credentials"
              columns={[
                { key: 'fp', title: 'Fingerprint', render: (_, c) => <Fingerprint value={c.fingerprint} /> },
                { key: 'kind', title: 'Kind', render: (_, c) => `${c.kind} · ${c.algorithm}` },
                {
                  key: 'state',
                  title: 'State',
                  render: (_, c) => <StateBadge kind="credential" state={c.state} />,
                },
                {
                  key: 'probe',
                  title: 'Last probe',
                  render: (_, c) =>
                    c.probe_error ? (
                      <span>
                        Failed: <span className="hp-mono">{revealControls(c.probe_error)}</span>
                      </span>
                    ) : c.probe_ok_at ? (
                      `OK ${formatDateTime(c.probe_ok_at)}`
                    ) : (
                      'Not probed'
                    ),
                },
                {
                  key: 'activated',
                  title: 'Activated',
                  render: (_, c) => formatDateTime(c.activated_at ?? null),
                },
                {
                  key: 'retire',
                  title: 'Retire after',
                  render: (_, c) => formatDateTime(c.retire_after ?? null),
                },
                {
                  key: 'actions',
                  title: <span className="hp-visually-hidden">Actions</span>,
                  render: (_, c) => {
                    const a = credentialActions(c, now);
                    return (
                      <Space size={4} wrap>
                        <Button
                          size="small"
                          type="link"
                          onClick={() => {
                            setSelected(c.id);
                          }}
                        >
                          Install line
                        </Button>
                        {a.probe ? <ProbeButton cred={c} roleId={roleId} /> : null}
                        {a.activate ? <ActivateButton cred={c} roleId={roleId} force={false} /> : null}
                        {a.forceActivate ? <ActivateButton cred={c} roleId={roleId} force /> : null}
                        {a.revoke ? <RevokeButton cred={c} roleId={roleId} /> : null}
                      </Space>
                    );
                  },
                },
              ]}
            />
            {focus ? (
              <Card size="small" type="inner" title={`Install on the destination (${focus.fingerprint})`}>
                <Space orientation="vertical" style={{ width: '100%' }}>
                  {credentialNextStep(focus, now) ? (
                    <Alert type="info" showIcon title={credentialNextStep(focus, now)} />
                  ) : null}
                  <CopyField label="authorized_keys line" value={focus.authorized_keys_line} />
                  <p style={{ margin: 0 }}>
                    Append this line to <code className="hp-mono">~/.ssh/authorized_keys</code> of the
                    role&apos;s remote user. The <code className="hp-mono">from=</code> and{' '}
                    <code className="hp-mono">restrict</code> options limit the key to the gateway.
                  </p>
                </Space>
              </Card>
            ) : null}
          </>
        )}
      </Space>
      <FormModal<{ private_key_pem: string }>
        open={importing}
        title="Import private key"
        okText="Import"
        formLabel="Import private key"
        onCancel={() => {
          setImporting(false);
        }}
        onSubmit={async (values) => {
          const cred = await api.call('post', '/api/v1/roles/{id}/credentials:import', {
            path: { id: roleId },
            body: { private_key_pem: values.private_key_pem },
          });
          setSelected(cred.id);
          await refresh();
          // Closing destroys the form, so the key material does not stay in memory.
          setImporting(false);
        }}
      >
        <>
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            title="Prefer generating keys in HallPass"
            description="An imported key already exists elsewhere. It is encrypted at rest after import and never shown again."
          />
          <Form.Item
            label="Private key (PEM or OpenSSH format)"
            name="private_key_pem"
            rules={[{ required: true, message: 'Paste the private key' }]}
          >
            <Input.TextArea rows={8} spellCheck={false} autoComplete="off" className="hp-mono" />
          </Form.Item>
        </>
      </FormModal>
    </Card>
  );
}
