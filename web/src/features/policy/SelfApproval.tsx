import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Card, Space, Switch } from 'antd';
import { useId } from 'react';

import { api } from '../../api/client';
import { selfApprovalQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { SelfApprovalSetting } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { ErrorState, LoadingState } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';

export const ALLOW_PHRASE = 'ALLOW SELF-APPROVAL';
export const PROHIBIT_PHRASE = 'PROHIBIT SELF-APPROVAL';

const SECONDARY = { color: 'var(--hp-color-text-secondary)', margin: 0 } as const;

/**
 * Self-approval prohibition (HP-POL-012): while on, operators listed as an agent's owners cannot approve
 * that agent's requests. Changing it needs policy.write, a typed confirmation and recent authentication with
 * MFA (enforced by the server, prompted by ReauthGate). The switch shows the server's value and moves only
 * after the server confirmed the change.
 */
export function SelfApprovalCard({ canWrite }: { canWrite: boolean }) {
  const queryClient = useQueryClient();
  const setting = useQuery(selfApprovalQueryOptions());
  const labelId = useId();

  let body;
  if (setting.isPending) {
    body = <LoadingState />;
  } else if (setting.isError) {
    body = <ErrorState error={setting.error} onRetry={() => void setting.refetch()} />;
  } else {
    const prohibited = setting.data.prohibit_self_approval;
    const next = !prohibited;
    body = (
      <Space orientation="vertical" size={8} style={{ width: '100%' }}>
        <Space wrap size={12}>
          {canWrite ? (
            <ConfirmAction<SelfApprovalSetting>
              label="Change self-approval"
              title={next ? 'Prohibit self-approval' : 'Allow self-approval'}
              danger={!next}
              typedConfirmation={next ? PROHIBIT_PHRASE : ALLOW_PHRASE}
              confirmLabel={next ? 'Prohibit self-approval' : 'Allow self-approval'}
              description={
                next ? (
                  <p style={{ margin: 0 }}>
                    Operators listed as an agent&apos;s owners will no longer be able to approve that
                    agent&apos;s requests.
                  </p>
                ) : (
                  <Alert
                    type="warning"
                    showIcon
                    title="Owners will be able to approve their own agents"
                    description="Turning the prohibition off lets an agent's owners approve that agent's access requests, removing the separation between the people who run an agent and the people who approve it."
                  />
                )
              }
              onConfirm={() =>
                api.call('put', '/api/v1/policy/self-approval', { body: { prohibit_self_approval: next } })
              }
              onSuccess={(result) => {
                queryClient.setQueryData(qk.selfApproval, result);
                // The change bumps the policy version.
                void queryClient.invalidateQueries({ queryKey: qk.policy });
              }}
              renderTrigger={({ open, disabled }) => (
                <Switch aria-labelledby={labelId} checked={prohibited} disabled={disabled} onChange={open} />
              )}
            />
          ) : null}
          <span id={labelId}>Prohibit self-approval</span>
          <StatusBadge tone={prohibited ? 'success' : 'warning'}>
            {prohibited ? 'Prohibited' : 'Allowed'}
          </StatusBadge>
        </Space>
        <p style={SECONDARY}>
          {prohibited
            ? "Agent owners cannot approve their own agents' requests."
            : "Agent owners can approve their own agents' requests."}
        </p>
      </Space>
    );
  }

  return (
    <Card size="small" title="Self-approval">
      {body}
    </Card>
  );
}
