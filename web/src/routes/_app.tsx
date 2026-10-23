import { createFileRoute, redirect } from '@tanstack/react-router';

import { api } from '../api/client';
import { isApiError } from '../api/errors';
import { meQueryOptions } from '../api/queries';
import { AppShell } from '../layout/AppShell';

/** Authenticated layout: every child route requires a valid session (`GET /me`). */
export const Route = createFileRoute('/_app')({
  beforeLoad: async ({ context, location }) => {
    try {
      // query() returns the cached /me while fresh (staleTime in meQueryOptions) and fetches otherwise.
      const me = await context.queryClient.query({
        ...meQueryOptions(),
        queryFn: ({ signal }) => api.getMe({ signal, authRedirect: false }),
      });
      return { me };
    } catch (error) {
      if (isApiError(error) && error.isUnauthenticated) {
        throw redirect({ to: '/login', search: { next: location.href } });
      }
      throw error;
    }
  },
  component: AppLayout,
});

function AppLayout() {
  const { me } = Route.useRouteContext();
  return <AppShell me={me} />;
}
