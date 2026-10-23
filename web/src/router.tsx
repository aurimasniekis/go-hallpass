import { createRouter } from '@tanstack/react-router';

import { createQueryClient } from './queryClient';
import { routeTree } from './routeTree.gen';

export const queryClient = createQueryClient();

export const router = createRouter({
  routeTree,
  context: { queryClient },
  defaultPreload: 'intent',
  // Freshness is TanStack Query's job; the router should always ask it.
  defaultPreloadStaleTime: 0,
  scrollRestoration: true,
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
