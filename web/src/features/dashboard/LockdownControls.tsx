import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, App, Space } from 'antd';

import { api } from '../../api/client';
import { systemStatusQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { SystemStatus } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { formatDateTime } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';

/**
 * Emergency lockdown controls (HP-GRT-011, PLAN §18.17). Enabling revokes every grant, cancels pending
 * requests and refuses new requests and channels; both directions need typed confirmation
 * (HP-UI-010) and recent authentication (enforced by the server, prompted by ReauthGate). The status
 * shown afterwards is the server's response, never assumed.
 */
export function LockdownControls({ status }: { status: SystemStatus | undefined }) {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const { message } = App.useApp();

  const onDone = (next: SystemStatus) => {
    queryClient.setQueryData(qk.systemStatus, next);
    void queryClient.invalidateQueries({ queryKey: qk.system });
    void queryClient.invalidateQueries({ queryKey: qk.grants });
    void queryClient.invalidateQueries({ queryKey: qk.requests });
    void queryClient.invalidateQueries({ queryKey: qk.activities });
    void message.success(next.lockdown ? 'Lockdown is active.' : 'Lockdown lifted.');
  };

  if (!status) {
    return null;
  }
  if (status.lockdown) {
    return can('system.lockdown.lift') ? (
      <ConfirmAction<SystemStatus>
        label="Lift lockdown"
        title="Lift emergency lockdown"
        typedConfirmation="LIFT"
        confirmLabel="Lift lockdown"
        description={
          <p>
            Agents will be able to request access again. Grants revoked by the lockdown stay revoked; agents
            must request new access. Investigate the cause before lifting.
          </p>
        }
        onConfirm={() => api.call('delete', '/api/v1/system/lockdown')}
        onSuccess={onDone}
      />
    ) : null;
  }
  return can('system.lockdown.enable') ? (
    <ConfirmAction<SystemStatus>
      label="Enable lockdown"
      title="Enable emergency lockdown"
      typedConfirmation="LOCKDOWN"
      confirmLabel="Enable lockdown"
      description={
        <ul style={{ paddingLeft: 20, margin: 0 }}>
          <li>Every active grant is revoked and live channels are terminated.</li>
          <li>Pending requests are canceled.</li>
          <li>New requests and channels are refused until an administrator lifts the lockdown.</li>
        </ul>
      }
      onConfirm={({ idempotencyKey }) => api.call('post', '/api/v1/system/lockdown', { idempotencyKey })}
      onSuccess={onDone}
    />
  ) : null;
}

/** Break-glass acknowledgement (system.settings, recent auth + MFA enforced by the server). */
export function BreakGlassAck() {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  if (!can('system.settings')) {
    return null;
  }
  return (
    <ConfirmAction<SystemStatus>
      label="Acknowledge"
      title="Acknowledge break-glass recovery"
      danger={false}
      confirmLabel="Acknowledge"
      description="Confirm that the recorded break-glass recoveries were reviewed in the audit log. This clears the alert."
      buttonProps={{ size: 'small' }}
      onConfirm={() => api.call('post', '/api/v1/system/breakglass-ack')}
      onSuccess={(next) => {
        queryClient.setQueryData(qk.systemStatus, next);
        void queryClient.invalidateQueries({ queryKey: qk.system });
      }}
    />
  );
}

/** App-wide banner while lockdown is on or a break-glass recovery is unacknowledged. */
export function LockdownBanner() {
  const { can } = usePermissions();
  const status = useQuery({ ...systemStatusQueryOptions(), enabled: can('dashboard.view') });
  const data = status.data;
  if (!data || (!data.lockdown && !data.breakglass_alert)) {
    return null;
  }
  return (
    <Space orientation="vertical" style={{ width: '100%' }} size={0}>
      {data.lockdown ? (
        <Alert
          banner
          type="error"
          role="alert"
          showIcon
          title="Emergency lockdown is active"
          description="All grants are revoked; new requests and channels are refused."
        />
      ) : null}
      {data.breakglass_alert ? (
        <Alert
          banner
          type="warning"
          role="alert"
          showIcon
          title="A break-glass recovery was used"
          description={`Recovery recorded ${formatDateTime(data.breakglass_at ?? null)}. Review the audit log and acknowledge it in System.`}
        />
      ) : null}
    </Space>
  );
}
