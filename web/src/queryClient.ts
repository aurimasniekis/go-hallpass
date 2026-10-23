import { QueryClient } from '@tanstack/react-query';

import { isApiError } from './api/errors';

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // SSE invalidates on change; this only bounds staleness when live updates are down.
        staleTime: 30_000,
        refetchOnWindowFocus: true,
        // Client errors (4xx) are final; retry transient failures twice.
        retry: (failureCount, error) =>
          !(isApiError(error) && error.status >= 400 && error.status < 500) && failureCount < 2,
      },
      mutations: {
        // Security mutations are never retried implicitly (HP-UI-012); callers use Idempotency-Key when needed.
        retry: false,
      },
    },
  });
}
