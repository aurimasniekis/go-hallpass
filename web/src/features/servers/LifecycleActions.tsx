import { CheckCircleOutlined, DeleteOutlined, StopOutlined } from '@ant-design/icons';
import { useQueryClient } from '@tanstack/react-query';
import { Space, type ButtonProps } from 'antd';
import type { ReactNode } from 'react';

import { api } from '../../api/client';
import { qk } from '../../api/queryKeys';
import { ConfirmAction } from '../../ds/ConfirmAction';

export type LifecycleKind =
  'server' | 'git remote' | 'API target' | 'role' | 'access profile' | 'API profile';

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
  compact = false,
}: {
  kind: LifecycleKind;
  target: LifecycleTarget;
  /** Called after a delete, e.g. to leave the deleted object's page. */
  onDeleted?: () => void;
  size?: 'small' | 'middle';
  /** Icon-only buttons (named for assistive technology and on hover), for table rows. */
  compact?: boolean;
}) {
  const queryClient = useQueryClient();
  const isServer = kind === 'server' || kind === 'git remote' || kind === 'API target';
  const isAPI = kind === 'API target' || kind === 'API profile';
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
  // Compact buttons keep their verb as the accessible name and hover title; the label is just the icon.
  const trigger = (verb: string, icon: ReactNode): { label: ReactNode; buttonProps: ButtonProps } =>
    compact
      ? {
          label: null,
          buttonProps: {
            size,
            icon,
            title: `${verb} ${target.alias}`,
            'aria-label': `${verb} ${target.alias}`,
          },
        }
      : { label: verb, buttonProps: { size } };
  const scope = isServer ? `, through all of its ${kind === 'server' ? 'roles' : 'access profiles'}` : '';
  const keyHome = kind === 'git remote' || kind === 'access profile' ? 'the git host' : 'the destination';
  return (
    <Space wrap size={8}>
      {target.enabled ? (
        <ConfirmAction
          {...trigger('Disable', <StopOutlined />)}
          title={`Disable ${kind} ${target.alias}`}
          confirmLabel="Disable"
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
          {...trigger('Enable', <CheckCircleOutlined />)}
          danger={false}
          title={`Enable ${kind} ${target.alias}`}
          confirmLabel="Enable"
          description={<p style={{ margin: 0 }}>Policy decides again who can see and request it.</p>}
          onConfirm={() => setEnabled(true)}
        />
      )}
      <ConfirmAction
        {...trigger('Delete', <DeleteOutlined />)}
        title={`Delete ${kind} ${target.alias}`}
        confirmLabel={`Delete ${kind}`}
        {...(isServer ? { typedConfirmation: target.alias } : {})}
        description={
          <>
            <p>
              {isAPI ? (
                <>
                  Active access ends{scope}, pending requests are canceled and the stored API credentials are
                  destroyed. Revoke the tokens at the API provider as well.
                </>
              ) : (
                <>
                  Active access ends{scope}, pending requests are canceled and the login keys are revoked.
                  Remove the keys from {keyHome} as well.
                </>
              )}
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
