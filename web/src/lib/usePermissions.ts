import { useQuery } from '@tanstack/react-query';
import { useCallback } from 'react';

import { meQueryOptions } from '../api/queries';
import type { Me } from '../api/types';
import { hasPermissions } from '../ds/permissions';

export interface Permissions {
  me: Me | undefined;
  /** True until `/me` has loaded; callers should render nothing permission-dependent meanwhile. */
  loading: boolean;
  can: (permission: string | readonly string[], mode?: 'all' | 'any') => boolean;
}

/**
 * Permission checks for showing or hiding UI, from `GET /me` `permissions`. Cosmetic only: the server
 * authorizes every request (HP-RBAC-*), and a hidden button is not a control.
 */
export function usePermissions(): Permissions {
  const me = useQuery(meQueryOptions());
  const granted = me.data?.permissions;
  const can = useCallback(
    (permission: string | readonly string[], mode: 'all' | 'any' = 'all') =>
      hasPermissions(granted, permission, mode),
    [granted],
  );
  return { me: me.data, loading: me.isPending, can };
}
