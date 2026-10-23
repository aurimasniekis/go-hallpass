import { useQuery } from '@tanstack/react-query';
import { Card, Space } from 'antd';

import { systemStatusQueryOptions } from '../../api/queries';
import { usePermissions } from '../../lib/usePermissions';
import { BreakGlassAck, LockdownControls } from '../dashboard/LockdownControls';

/** Emergency lockdown (PLAN §18.17) and break-glass acknowledgement, shared with the dashboard. */
export function SystemControls() {
  const { can } = usePermissions();
  const status = useQuery({ ...systemStatusQueryOptions(), enabled: can('dashboard.view') });
  return (
    <Card title="Emergency lockdown" size="small">
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <p style={{ margin: 0 }}>
          Lockdown revokes every grant, cancels pending requests and refuses new requests and channels until
          an administrator lifts it. Both directions need recent authentication.
        </p>
        <LockdownControls status={status.data} />
        {status.data?.breakglass_alert ? <BreakGlassAck /> : null}
      </Space>
    </Card>
  );
}
