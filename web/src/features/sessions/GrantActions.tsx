import { useQueryClient } from '@tanstack/react-query';
import { Input } from 'antd';
import { useId, useState } from 'react';

import { api } from '../../api/client';
import { qk } from '../../api/queryKeys';
import type { Grant } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { usePermissions } from '../../lib/usePermissions';

/**
 * Revoke an active grant (HP-GRT-009): ends its access session and live channels. The reason is stored
 * sealed and audited. Success is shown only after the server returns the revoked grant (HP-UI-012).
 */
export function RevokeGrantButton({
  grant,
  size = 'middle',
  onRevoked,
}: {
  grant: Pick<Grant, 'id' | 'state'>;
  size?: 'small' | 'middle';
  onRevoked?: (g: Grant) => void;
}) {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const [reason, setReason] = useState('');
  const id = useId();
  if (!can('grants.revoke') || grant.state !== 'active') {
    return null;
  }
  return (
    <ConfirmAction<Grant>
      label="Revoke"
      title="Revoke this grant?"
      confirmLabel="Revoke grant"
      buttonProps={{ size, 'aria-label': `Revoke grant ${grant.id}` }}
      onOpen={() => {
        setReason('');
      }}
      description={
        <>
          <p>The agent loses access immediately and every live channel of this grant is terminated.</p>
          <label htmlFor={id} style={{ display: 'block', marginBottom: 4 }}>
            Reason (recorded in the audit log)
          </label>
          <Input.TextArea
            id={id}
            value={reason}
            maxLength={1000}
            rows={3}
            onChange={(e) => {
              setReason(e.target.value);
            }}
          />
        </>
      }
      onConfirm={({ idempotencyKey }) =>
        api.call('post', '/api/v1/grants/{id}/revoke', {
          path: { id: grant.id },
          body: reason.trim() ? { reason: reason.trim() } : {},
          idempotencyKey,
        })
      }
      onSuccess={(g) => {
        for (const key of [
          qk.grants,
          qk.grant(grant.id),
          qk.accessSessions,
          qk.accessSessionRoot,
          qk.activities,
          qk.system,
        ]) {
          void queryClient.invalidateQueries({ queryKey: key });
        }
        onRevoked?.(g);
      }}
    />
  );
}
