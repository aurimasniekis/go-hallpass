import { useQueryClient } from '@tanstack/react-query';
import { Space } from 'antd';

import { api } from '../../api/client';
import { qk } from '../../api/queryKeys';
import { ConfirmAction } from '../../ds/ConfirmAction';

export type LifecycleKind = 'server' | 'git remote' | 'role' | 'access profile';

export interface LifecycleTarget {
  id: string;
  alias: string;
  enabled: boolean;
}

/**
 * Disable/enable and delete for servers, git remotes, roles and access profiles. Disabling ends access and can be
 * undone. Deleting also revokes the login keys and cannot be undone; the record stays only so history can name it.
 * Deleting a server or git remote takes all of its roles with it and needs the name typed (HP-UI-010).
 */
export function LifecycleActions({
  kind,
  target,
  onDeleted,
  size,
}: {
  kind: LifecycleKind;
  target: LifecycleTarget;
  /** Called after a delete, e.g. to leave the deleted object's page. */
  onDeleted?: () => void;
  size?: 'small' | 'middle';
}) {
  const queryClient = useQueryClient();
  const isServer = kind === 'server' || kind === 'git remote';
  const refresh = async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.servers }),
      queryClient.invalidateQueries({ queryKey: isServer ? qk.server(target.id) : qk.role(target.id) }),
      queryClient.invalidateQueries({ queryKey: qk.roles }),
      queryClient.invalidateQueries({ queryKey: qk.effectiveAccess }),
    ]);
  };
  const setEnabled = async (enabled: boolean) => {
    const action = enabled ? 'enable' : 'disable';
    if (isServer) {
      await api.call('post', `/api/v1/servers/{id}/${action}`, { path: { id: target.id } });
    } else {
      await api.call('post', `/api/v1/roles/{id}/${action}`, { path: { id: target.id } });
    }
    await refresh();
  };
  const scope = isServer ? `, through all of its ${kind === 'git remote' ? 'access profiles' : 'roles'}` : '';
  const keyHome = kind === 'git remote' || kind === 'access profile' ? 'the git host' : 'the destination';
  return (
    <Space wrap size={8}>
      {target.enabled ? (
        <ConfirmAction
          label="Disable"
          title={`Disable ${kind} ${target.alias}`}
          confirmLabel="Disable"
          buttonProps={{ size }}
          description={
            <p style={{ margin: 0 }}>
              Agents can no longer see or request it{scope}. Active access ends within seconds and pending
              requests are canceled. You can enable it again later.
            </p>
          }
          onConfirm={() => setEnabled(false)}
        />
      ) : (
        <ConfirmAction
          label="Enable"
          danger={false}
          title={`Enable ${kind} ${target.alias}`}
          confirmLabel="Enable"
          buttonProps={{ size }}
          description={<p style={{ margin: 0 }}>Policy decides again who can see and request it.</p>}
          onConfirm={() => setEnabled(true)}
        />
      )}
      <ConfirmAction
        label="Delete"
        title={`Delete ${kind} ${target.alias}`}
        confirmLabel={`Delete ${kind}`}
        buttonProps={{ size }}
        {...(isServer ? { typedConfirmation: target.alias } : {})}
        description={
          <>
            <p>
              Active access ends{scope}, pending requests are canceled and the login keys are revoked. Remove
              the keys from {keyHome} as well.
            </p>
            <p style={{ margin: 0 }}>
              This cannot be undone. Past sessions and the audit log keep its name, and the name can be used
              again.
            </p>
          </>
        }
        onConfirm={async () => {
          if (isServer) {
            await api.call('delete', '/api/v1/servers/{id}', { path: { id: target.id } });
          } else {
            await api.call('delete', '/api/v1/roles/{id}', { path: { id: target.id } });
          }
        }}
        onSuccess={() => {
          onDeleted?.();
          void refresh();
        }}
      />
    </Space>
  );
}
