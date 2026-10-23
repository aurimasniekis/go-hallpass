import { CheckCircleFilled } from '@ant-design/icons';
import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Alert, Button, Card, Form, Radio, Space, Steps } from 'antd';
import { useMemo, useState, type ReactNode } from 'react';

import { api } from '../../../api/client';
import { errorMessage } from '../../../api/errors';
import {
  credentialsQueryOptions,
  hostIdentitiesQueryOptions,
  policyRulesQueryOptions,
  serverQueryOptions,
  serverRolesQueryOptions,
} from '../../../api/queries';
import { qk } from '../../../api/queryKeys';
import type { LoginCredential, Role, Server } from '../../../api/types';
import { CodeBlock } from '../../../ds/CodeBlock';
import { KeyValueGrid } from '../../../ds/KeyValueGrid';
import { PageHeader } from '../../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../../ds/states';
import { applyFieldErrors } from '../../../lib/formErrors';
import { newIdempotencyKey } from '../../../lib/idempotency';
import { labelsToTags } from '../../../lib/labels';
import { usePermissions } from '../../../lib/usePermissions';
import { TagList } from '../../agents/AgentsPage';
import { conflictHint, LabelFormatError, orDash } from '../formUtils';
import { HostCAPanel } from '../HostCA';
import { HostIdentities } from '../HostIdentities';
import { ServerFormFields } from '../ServerFormFields';
import { toServerInput, type ServerFormValues } from '../serverForm';
import { ServerRoles } from '../ServerRoles';
import { AddressCell } from '../ServersPage';
import { AccessStep } from './AccessStep';
import {
  effectiveStep,
  nextStep,
  previousStep,
  roleLogin,
  STEP_TITLES,
  stepStates,
  STEPS,
  targetsServer,
  type RoleLogin,
  type StepKey,
  type WizardFacts,
} from './model';
import { RoleLoginSetup } from './RoleLoginSetup';

export interface WizardLocation {
  server?: string;
  step?: StepKey;
}

function CreateServer({ onCreated }: { onCreated: (server: Server) => void }) {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const [form] = Form.useForm<ServerFormValues>();
  const [idempotencyKey] = useState(newIdempotencyKey);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const showAddress = can('inventory.address.read');
  const submit = async (values: ServerFormValues) => {
    setPending(true);
    setError(null);
    try {
      const server = await api.call('post', '/api/v1/servers', {
        body: toServerInput(values, { includeAddress: showAddress }),
        idempotencyKey,
      });
      await queryClient.invalidateQueries({ queryKey: qk.servers });
      onCreated(server);
    } catch (e) {
      if (!(e instanceof LabelFormatError)) {
        applyFieldErrors(form, e);
      }
      setError(e);
    } finally {
      setPending(false);
    }
  };
  return (
    <Form<ServerFormValues>
      form={form}
      layout="vertical"
      requiredMark="optional"
      aria-label="New server"
      initialValues={{ enabled: true, port: 22 }}
      onFinish={(v) => void submit(v)}
      className="hp-wizard-form"
    >
      <ServerFormFields mode="create" showAddress={showAddress} />
      {error !== null ? (
        <Alert
          type="error"
          showIcon
          title={errorMessage(error)}
          description={conflictHint(error) ?? undefined}
          style={{ marginBottom: 16 }}
        />
      ) : null}
      <Button type="primary" htmlType="submit" loading={pending}>
        Create server and continue
      </Button>
    </Form>
  );
}

function IdentityStep({
  server,
  canWrite,
  canAddress,
}: {
  server: Server;
  canWrite: boolean;
  canAddress: boolean;
}) {
  const [mode, setMode] = useState<'keys' | 'ca'>(server.host_ca_id ? 'ca' : 'keys');
  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <p className="hp-card-intro" style={{ margin: 0 }}>
        The gateway refuses to connect until it can verify the destination. Either pin its host key (scan it
        and compare the fingerprint with the host itself, or paste the key), or trust a host certificate
        authority that signs the host key.
      </p>
      <Radio.Group
        value={mode}
        optionType="button"
        onChange={(e) => {
          setMode(e.target.value as 'keys' | 'ca');
        }}
        options={[
          { value: 'keys', label: 'Pin host keys' },
          { value: 'ca', label: 'Trust a host CA' },
        ]}
      />
      {mode === 'keys' ? (
        <>
          <div>
            Compare scanned fingerprints with the output of this command on the destination&apos;s console
            (not over the same network path):
            <CodeBlock code={'for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$f"; done'} />
          </div>
          {canAddress ? (
            <HostIdentities serverId={server.id} canWrite={canWrite} />
          ) : (
            <PermissionDenied detail="Host identities need the inventory.address.read permission." />
          )}
        </>
      ) : (
        <HostCAPanel server={server} canWrite={canWrite} />
      )}
    </Space>
  );
}

function Summary({
  server,
  facts,
  roles,
  logins,
}: {
  server: Server;
  facts: WizardFacts;
  roles: Role[];
  logins: Record<string, RoleLogin>;
}) {
  const states = stepStates(facts);
  const firstRole = roles[0]?.alias ?? '<role>';
  const items: { key: StepKey; text: string }[] = [
    { key: 'server', text: `Server ${server.alias} exists` },
    { key: 'identity', text: 'The gateway can verify the destination host' },
    { key: 'roles', text: `${String(roles.length)} role${roles.length === 1 ? '' : 's'} defined` },
    {
      key: 'credentials',
      text: `${String(Object.values(logins).filter((l) => l === 'active' || l === 'certificate').length)} of ${String(roles.length)} roles can log in`,
    },
    { key: 'access', text: facts.accessRules?.length ? 'Agents have an access rule' : 'No access rule yet' },
  ];
  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <ul className="hp-checklist">
        {items.map((i) => {
          const done = states.find((s) => s.key === i.key)?.done ?? false;
          return (
            <li key={i.key} className={done ? 'hp-checklist__done' : 'hp-checklist__todo'}>
              {done ? <CheckCircleFilled aria-hidden="true" /> : <span aria-hidden="true">○</span>}
              <span>
                {i.text}
                <span className="hp-visually-hidden">{done ? ' (done)' : ' (not done)'}</span>
              </span>
            </li>
          );
        })}
      </ul>
      <div>
        Agents in the chosen groups can now run, for example:
        <CodeBlock code={`ssh <gateway> exec ${server.alias} --role ${firstRole} --reason 'why' -- uptime`} />
      </div>
      <Space wrap>
        <Link to="/servers/$id" params={{ id: server.id }}>
          Open the server
        </Link>
        <Link to="/servers/$id" params={{ id: server.id }} search={{ tab: 'roles' }}>
          Roles
        </Link>
        <Link to="/policy">Policy</Link>
        <Link to="/requests">Requests</Link>
      </Space>
    </Space>
  );
}

/**
 * Guided server onboarding: server → host identity → roles → login credentials → access → summary.
 * The current server and step live in the URL; everything else is read back from the API, so the flow
 * survives a reload and can be resumed from the server page.
 */
export function OnboardingWizard({
  location,
  onNavigate,
}: {
  location: WizardLocation;
  onNavigate: (next: WizardLocation, replace?: boolean) => void;
}) {
  const { can, loading } = usePermissions();
  const queryClient = useQueryClient();
  const serverId = location.server;
  const canRead = can('inventory.read');
  const canWrite = can('inventory.write');
  const canAddress = can('inventory.address.read');
  const canCreds = can('credentials.manage');
  const server = useQuery({ ...serverQueryOptions(serverId ?? ''), enabled: Boolean(serverId) && canRead });
  const identities = useQuery({
    ...hostIdentitiesQueryOptions(serverId ?? ''),
    enabled: Boolean(serverId) && canAddress,
  });
  const roles = useQuery({
    ...serverRolesQueryOptions(serverId ?? ''),
    enabled: Boolean(serverId) && canRead,
  });
  const roleItems = useMemo(() => roles.data?.items ?? [], [roles.data]);
  const creds = useQueries({
    queries: roleItems.map((r) => ({ ...credentialsQueryOptions(r.id), enabled: canCreds })),
  });
  const rules = useQuery({ ...policyRulesQueryOptions(), enabled: Boolean(serverId) && can('policy.read') });
  const [certBound, setCertBound] = useState<Record<string, boolean>>({});
  const [accessSkipped, setAccessSkipped] = useState(false);

  const credentialsByRole: Record<string, LoginCredential[] | undefined> = {};
  roleItems.forEach((r, i) => {
    credentialsByRole[r.id] = creds[i]?.data?.items;
  });
  const logins: Record<string, RoleLogin> = {};
  for (const r of roleItems) {
    logins[r.id] = roleLogin(credentialsByRole[r.id], certBound[r.id] ?? false);
  }
  const serverRules = (rules.data?.items ?? []).filter((r) => serverId && targetsServer(r, serverId));
  const facts: WizardFacts = {
    server: server.data ?? null,
    identities: identities.data?.items,
    roles: roleItems,
    logins,
    accessRules: serverRules,
    accessSkipped,
  };

  const title = 'New server (guided)';
  const back = <Link to="/servers">← Servers</Link>;
  if (loading) {
    return <LoadingState />;
  }
  if (!canRead || !canWrite) {
    return (
      <>
        <PageHeader title={title} above={back} />
        <PermissionDenied detail="Onboarding a server needs the inventory.read and inventory.write permissions." />
      </>
    );
  }
  if (serverId && server.isPending) {
    return (
      <>
        <PageHeader title={title} above={back} />
        <LoadingState />
      </>
    );
  }
  if (serverId && server.isError) {
    return (
      <>
        <PageHeader title={title} above={back} />
        <ErrorState error={server.error} onRetry={() => void server.refetch()} />
      </>
    );
  }

  const step = effectiveStep(location.step, facts);
  const states = stepStates(facts);
  const go = (next: StepKey) => {
    onNavigate({ ...(serverId ? { server: serverId } : {}), step: next });
  };
  const s = server.data;
  const current = states.find((x) => x.key === step);

  let body: ReactNode = null;
  let canContinue = current?.done ?? false;
  if (step === 'server') {
    body = s ? (
      <KeyValueGrid
        items={[
          { key: 'alias', label: 'Alias', value: s.alias },
          { key: 'addr', label: 'Address', value: <AddressCell server={s} /> },
          { key: 'desc', label: 'Description', value: orDash(s.description), span: 2 },
          { key: 'labels', label: 'Labels', value: <TagList values={labelsToTags(s.labels)} /> },
        ]}
      />
    ) : (
      <CreateServer
        onCreated={(created) => {
          queryClient.setQueryData(qk.server(created.id), created);
          onNavigate({ server: created.id, step: 'identity' });
        }}
      />
    );
  } else if (s && step === 'identity') {
    body = <IdentityStep server={s} canWrite={canWrite} canAddress={canAddress} />;
  } else if (s && step === 'roles') {
    body = (
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <p className="hp-card-intro" style={{ margin: 0 }}>
          A role is a login identity on the destination (the remote user) plus its limits: durations,
          capabilities and recording. Agents request access to a role, never to the server as a whole.
        </p>
        <ServerRoles serverId={s.id} canWrite={canWrite} />
      </Space>
    );
  } else if (s && step === 'credentials') {
    body = (
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <p className="hp-card-intro" style={{ margin: 0 }}>
          Each role needs a way for the gateway to log in to the destination: a login key installed in the
          remote user&apos;s <code className="hp-mono">authorized_keys</code>, or a certificate signed by a
          Hallpass user CA.
        </p>
        {roleItems.map((r, i) => (
          <RoleLoginSetup
            key={r.id}
            role={r}
            credentials={credentialsByRole[r.id]}
            login={logins[r.id] ?? 'unknown'}
            canManage={canCreds && !creds[i]?.isError}
            onCertificateBound={() => {
              setCertBound((b) => ({ ...b, [r.id]: true }));
            }}
          />
        ))}
      </Space>
    );
  } else if (s && step === 'access') {
    canContinue = true;
    body = (
      <AccessStep
        server={s}
        roles={roleItems}
        rules={can('policy.read') ? serverRules : undefined}
        onDone={() => {
          go('done');
        }}
        onSkip={() => {
          setAccessSkipped(true);
          go('done');
        }}
      />
    );
  } else if (s && step === 'done') {
    body = <Summary server={s} facts={facts} roles={roleItems} logins={logins} />;
  }

  return (
    <>
      <PageHeader
        title={s ? `Set up ${s.alias}` : title}
        above={
          s ? (
            <Link to="/servers/$id" params={{ id: s.id }}>
              ← {s.alias}
            </Link>
          ) : (
            back
          )
        }
        description="From nothing to a working login: the server, how the gateway verifies it, roles, login credentials and who may request access. Everything created is kept if you stop; resume from the server page."
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card size="small">
          <Steps
            size="small"
            current={STEPS.indexOf(step)}
            onChange={(i) => {
              const key = STEPS[i];
              if (key && states[i]?.available) {
                go(key);
              }
            }}
            items={states.map((st) => ({
              title: STEP_TITLES[st.key],
              disabled: !st.available,
              status: st.key === step ? 'process' : st.done ? 'finish' : 'wait',
            }))}
          />
        </Card>
        <Card size="small" title={`${String(STEPS.indexOf(step) + 1)}. ${STEP_TITLES[step]}`}>
          {body}
        </Card>
        {step !== 'server' || s ? (
          <div className="hp-wizard-nav">
            {step !== 'server' ? (
              <Button
                onClick={() => {
                  go(previousStep(step));
                }}
              >
                Back
              </Button>
            ) : (
              <span />
            )}
            {step !== 'done' && step !== 'access' ? (
              <Space>
                {!canContinue ? (
                  <span className="hp-legend">
                    {step === 'identity'
                      ? 'Confirm a host key or bind a host CA to continue.'
                      : step === 'roles'
                        ? 'Create at least one role to continue.'
                        : 'Every enabled role needs an active login to finish this step.'}
                  </span>
                ) : null}
                <Button
                  type={canContinue ? 'primary' : 'default'}
                  onClick={() => {
                    go(nextStep(step));
                  }}
                  disabled={!(states[STEPS.indexOf(nextStep(step))]?.available ?? false)}
                >
                  {canContinue ? 'Next' : 'Skip for now'}
                </Button>
              </Space>
            ) : null}
          </div>
        ) : null}
      </Space>
    </>
  );
}
