import { QueryClient } from '@tanstack/react-query';

import { isApiError } from './api/errors';

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // SSE invalidates on change; this only bounds staleness when live updates are down.
        staleTime: 30_000,
        refetchOnWindowFocus: true,
        // Client errors (4xx) are final, except rate limiting (429), which backs off and retries; retry other
        // transient failures twice.
        retry: (failureCount, error) => {
          if (isApiError(error) && error.status === 429) {
            return failureCount < 5;
          }
          return !(isApiError(error) && error.status >= 400 && error.status < 500) && failureCount < 2;
        },
        retryDelay: (attempt, error) =>
          isApiError(error) && error.status === 429
            ? Math.min(2_000 * 2 ** attempt, 30_000)
            : Math.min(1_000 * 2 ** attempt, 10_000),
      },
      mutations: {
        // Security mutations are never retried implicitly (HP-UI-012); callers use Idempotency-Key when needed.
        retry: false,
      },
    },
  });
}
