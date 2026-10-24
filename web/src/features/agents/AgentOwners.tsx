import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Card, Select, Space } from 'antd';
import { useId, useState } from 'react';

import { api } from '../../api/client';
import { agentOwnersQueryOptions, operatorsQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { AgentOwners as AgentOwnersResult } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { ErrorState, LoadingState } from '../../ds/states';
import { TagsInput } from '../../ds/TagsInput';
import { usePermissions } from '../../lib/usePermissions';
import { OperatorName } from '../../shared/names';

/** Server-side bound on the owner list of one agent (internal/policy MaxAgentOwners). */
export const MAX_AGENT_OWNERS = 64;

export const OWNERS_EXPLANATION =
  "Owners cannot approve this agent's requests while self-approval is prohibited.";

const SECONDARY = { color: 'var(--hp-color-text-secondary)', margin: 0 } as const;

/** Multi-select of operators; free operator IDs when the operator list is not readable. */
function OwnerPicker({
  id,
  value,
  onChange,
}: {
  id: string;
  value: string[];
  onChange: (owners: string[]) => void;
}) {
  const { can } = usePermissions();
  const canList = can('operators.manage');
  const operators = useQuery({ ...operatorsQueryOptions(), enabled: canList });
  if (!canList) {
    return (
      <>
        <TagsInput id={id} aria-label="Owners" placeholder="Operator IDs" value={value} onChange={onChange} />
        <p style={SECONDARY}>Operator names need the operators.manage permission; enter operator IDs.</p>
      </>
    );
  }
  const known = operators.data?.items ?? [];
  const options = [
    ...known.map((o) => ({
      value: o.id,
      label: o.email ? `${o.display_name} <${o.email}>` : o.display_name,
    })),
    // Current owners missing from the list (e.g. still loading) stay visible as IDs.
    ...value.filter((v) => !known.some((o) => o.id === v)).map((v) => ({ value: v, label: v })),
  ];
  return (
    <Select<string[]>
      id={id}
      mode="multiple"
      aria-label="Owners"
      placeholder="Choose operators"
      loading={operators.isPending}
      value={value}
      onChange={onChange}
      options={options}
      showSearch={{ optionFilterProp: 'label' }}
      style={{ width: '100%' }}
    />
  );
}

/**
 * Agent owners (HP-POL-012): operators who may not approve the agent's requests while self-approval is
 * prohibited. Shown with policy.read; replacing the list needs policy.write plus recent authentication and
 * MFA (the server answers `reauth_required`/`mfa_required`, and ReauthGate prompts and retries).
 */
export function AgentOwners({ agentId }: { agentId: string }) {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const owners = useQuery(agentOwnersQueryOptions(agentId));
  const [draft, setDraft] = useState<string[]>([]);
  const pickerId = useId();
  const canWrite = can('policy.write');
  const tooMany = draft.length > MAX_AGENT_OWNERS;
  const current = owners.data?.owners;

  return (
    <Card
      size="small"
      title="Owners"
      extra={
        canWrite && current ? (
          <ConfirmAction<AgentOwnersResult>
            label="Edit owners"
            title="Edit agent owners"
            danger={false}
            confirmLabel="Save owners"
            buttonProps={{ size: 'small' }}
            confirmDisabled={tooMany}
            onOpen={() => {
              setDraft([...current]);
            }}
            description={
              <Space orientation="vertical" size={8} style={{ width: '100%' }}>
                <p style={{ margin: 0 }}>{OWNERS_EXPLANATION}</p>
                <label htmlFor={pickerId}>Owners</label>
                <OwnerPicker id={pickerId} value={draft} onChange={setDraft} />
                {tooMany ? (
                  <Alert
                    type="error"
                    showIcon
                    title={`An agent can have at most ${String(MAX_AGENT_OWNERS)} owners.`}
                  />
                ) : null}
              </Space>
            }
            onConfirm={() =>
              api.call('put', '/api/v1/agents/{id}/owners', {
                path: { id: agentId },
                body: { owners: draft },
              })
            }
            onSuccess={(result) => {
              queryClient.setQueryData(qk.agentOwners(agentId), result);
              // Owner changes bump the policy version.
              void queryClient.invalidateQueries({ queryKey: qk.policy });
            }}
          />
        ) : null
      }
    >
      <Space orientation="vertical" size={8} style={{ width: '100%' }}>
        <p style={SECONDARY}>{OWNERS_EXPLANATION}</p>
        {owners.isPending ? (
          <LoadingState />
        ) : owners.isError ? (
          <ErrorState error={owners.error} onRetry={() => void owners.refetch()} />
        ) : owners.data.owners.length === 0 ? (
          <p style={{ margin: 0 }}>No owners.</p>
        ) : (
          <ul aria-label="Agent owners" style={{ margin: 0, paddingLeft: 20 }}>
            {owners.data.owners.map((id) => (
              <li key={id}>
                <OperatorName id={id} />
              </li>
            ))}
          </ul>
        )}
      </Space>
    </Card>
  );
}
