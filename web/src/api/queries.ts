import { queryOptions } from '@tanstack/react-query';

import { api } from './client';
import { qk } from './queryKeys';

export const meQueryOptions = () =>
  queryOptions({
    queryKey: qk.me,
    queryFn: ({ signal }) => api.getMe({ signal }),
    staleTime: 60_000,
  });

export const authConfigQueryOptions = () =>
  queryOptions({
    queryKey: qk.authConfig,
    queryFn: ({ signal }) => api.getAuthConfig({ signal }),
    staleTime: 5 * 60_000,
  });
