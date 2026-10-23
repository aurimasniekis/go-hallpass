import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';

import { meQueryOptions } from '../api/queries';
import { hasPermissions } from './permissions';
import { PermissionDenied } from './states';

export interface PermissionGateProps {
  permission: string | readonly string[];
  mode?: 'all' | 'any';
  children: ReactNode;
  /** Shown when the permission is missing. Defaults to the permission-denied state; pass `null` to hide. */
  fallback?: ReactNode;
  /** Explicit permission list (otherwise read from `GET /me`). */
  permissions?: readonly string[];
}

export function PermissionGate({
  permission,
  mode = 'all',
  children,
  fallback,
  permissions,
}: PermissionGateProps) {
  const me = useQuery({ ...meQueryOptions(), enabled: permissions === undefined });
  const granted = permissions ?? me.data?.permissions;
  if (permissions === undefined && me.isPending) {
    return null;
  }
  if (hasPermissions(granted, permission, mode)) {
    return <>{children}</>;
  }
  return <>{fallback === undefined ? <PermissionDenied /> : fallback}</>;
}
