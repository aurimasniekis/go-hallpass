import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Alert, Button, Card, Input, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { agentQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { labelsToTags } from '../../lib/labels';
import { usePermissions } from '../../lib/usePermissions';
import { OperatorName } from '../../shared/names';
import { EffectiveAccessCard } from '../servers/EffectiveAccessTable';
import { FormModal } from '../servers/FormModal';
import { AgentFormFields } from './AgentFormFields';
import { agentFormValues, toAgentPatch, type AgentFormValues } from './agentForm';
import { AgentConnect } from './AgentConnect';
import { AgentKeys } from './AgentKeys';
import { AgentOwners } from './AgentOwners';
import { EnabledBadge, TagList } from './AgentsPage';

export function AgentDetailPage({ id }: { id: string }) {
  const { can, loading } = usePermissions();
  const queryClient = useQueryClient();
  const query = useQuery({ ...agentQueryOptions(id), enabled: can('inventory.read') });
  const [editing, setEditing] = useState(false);
  const [reason, setReason] = useState('');
  const navigate = useNavigate();
  const canWrite = can('inventory.write');

  const back = <Link to="/agents">← Agents</Link>;
  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Agent" above={back} />
        <PermissionDenied />
      </>
    );
  }
  if (query.isPending) {
    return (
      <>
        <PageHeader title="Agent" above={back} />
        <LoadingState />
      </>
    );
  }
  if (query.isError) {
    return (
      <>
        <PageHeader title="Agent" above={back} />
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      </>
    );
  }
  const agent = query.data;
  const refresh = () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.agent(id) }),
      queryClient.invalidateQueries({ queryKey: qk.agents }),
      queryClient.invalidateQueries({ queryKey: qk.effectiveAccess }),
    ]);

  return (
    <>
      <PageHeader
        above={back}
        title={agent.name}
        description={<EnabledBadge enabled={agent.enabled} />}
        extra={
          canWrite && !agent.deleted_at ? (
            <Space wrap>
              <Button
                onClick={() => {
                  setEditing(true);
                }}
              >
                Edit
              </Button>
              {agent.enabled ? (
                <ConfirmAction
                  label="Disable"
                  title="Disable agent"
                  confirmLabel="Disable agent"
                  onOpen={() => {
                    setReason('');
                  }}
                  description={
                    <>
                      <p>The agent can no longer authenticate or request access until it is enabled again.</p>
                      <label htmlFor="agent-disable-reason">Reason (recorded in the audit log)</label>
                      <Input
                        id="agent-disable-reason"
                        value={reason}
                        maxLength={1000}
                        onChange={(e) => {
                          setReason(e.target.value);
                        }}
                      />
                    </>
                  }
                  onConfirm={({ idempotencyKey }) =>
                    api.call('post', '/api/v1/agents/{id}/disable', {
                      path: { id },
                      body: reason.trim() ? { reason: reason.trim() } : {},
                      idempotencyKey,
                    })
                  }
                  onSuccess={() => void refresh()}
                />
              ) : (
                <ConfirmAction
                  label="Enable"
                  danger={false}
                  title="Enable agent"
                  confirmLabel="Enable agent"
                  description="The agent may authenticate again with its active keys. Policy still decides what it can reach."
                  onConfirm={() => api.call('post', '/api/v1/agents/{id}/enable', { path: { id } })}
                  onSuccess={() => void refresh()}
                />
              )}
              <ConfirmAction
                label="Delete"
                title={`Delete agent ${agent.name}`}
                confirmLabel="Delete agent"
                typedConfirmation={agent.name}
                description={
                  <>
                    <p>
                      Its access ends, pending requests are canceled and every key is revoked. A revoked key
                      can never be registered again, so a new agent needs a new key.
                    </p>
                    <p style={{ margin: 0 }}>
                      This cannot be undone. Past sessions and the audit log keep its name, and the name can
                      be used again.
                    </p>
                  </>
                }
                onConfirm={async () => {
                  await api.call('delete', '/api/v1/agents/{id}', { path: { id } });
                }}
                onSuccess={() => {
                  void navigate({ to: '/agents' });
                  void refresh();
                }}
              />
            </Space>
          ) : null
        }
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {agent.deleted_at ? (
          <Alert
            type="warning"
            showIcon
            title={`Deleted ${formatDateTime(agent.deleted_at)}`}
            description="Kept only so past sessions and the audit log can name it. It cannot authenticate."
          />
        ) : null}
        <Card size="small" title="Details">
          <KeyValueGrid
            items={[
              { span: 2, key: 'id', label: 'Agent ID', value: <code className="hp-mono">{agent.id}</code> },
              { span: 2, key: 'desc', label: 'Description', value: agent.description || '—' },
              { key: 'groups', label: 'Groups', value: <TagList values={agent.groups} /> },
              { key: 'labels', label: 'Labels', value: <TagList values={labelsToTags(agent.labels)} /> },
              {
                key: 'cidrs',
                label: 'Source CIDRs',
                value: agent.source_cidrs?.length ? <TagList values={agent.source_cidrs} /> : 'Any source',
              },
              { key: 'version', label: 'Version', value: agent.version },
              {
                key: 'created',
                label: 'Created',
                value: (
                  <>
                    {formatDateTime(agent.created_at)}
                    {agent.created_by ? (
                      <>
                        {' '}
                        by <OperatorName id={agent.created_by.replace(/^operator:/, '')} />
                      </>
                    ) : null}
                  </>
                ),
              },
              { key: 'updated', label: 'Updated', value: formatDateTime(agent.updated_at) },
              ...(agent.disabled_at
                ? [{ key: 'disabled', label: 'Disabled at', value: formatDateTime(agent.disabled_at) }]
                : []),
            ]}
          />
        </Card>
        <AgentKeys agentId={id} keys={agent.keys} canWrite={canWrite} />
        {agent.deleted_at ? null : <AgentConnect agentName={agent.name} />}
        {can('policy.read') ? <AgentOwners agentId={id} /> : null}
        {can('policy.read') ? <EffectiveAccessCard kind="agent" id={id} /> : null}
      </Space>
      <FormModal<AgentFormValues>
        open={editing}
        title="Edit agent"
        okText="Save"
        formLabel="Edit agent"
        initialValues={agentFormValues(agent)}
        onCancel={() => {
          setEditing(false);
        }}
        onSubmit={async (values) => {
          await api.call('patch', '/api/v1/agents/{id}', {
            path: { id },
            body: toAgentPatch(values, agent.version),
            ifMatch: agent.version,
          });
          await refresh();
          setEditing(false);
        }}
      >
        <AgentFormFields mode="edit" />
      </FormModal>
    </>
  );
}
