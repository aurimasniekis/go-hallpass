import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { useCallback } from 'react';

import { api } from '../api/client';
import { safeNextPath } from '../features/auth/redirect';
import { LoginPage } from '../features/auth/LoginPage';

interface LoginSearch {
  next?: string;
  /** Stable error code from a failed SSO flow (`/login?sso_error=<code>`). */
  sso_error?: string;
}

export const Route = createFileRoute('/login')({
  validateSearch: (search: Record<string, unknown>): LoginSearch => ({
    ...(typeof search.next === 'string' ? { next: search.next } : {}),
    ...(typeof search.sso_error === 'string' && /^[a-z0-9_.-]{1,64}$/.test(search.sso_error)
      ? { sso_error: search.sso_error }
      : {}),
  }),
  component: LoginRoute,
});

function LoginRoute() {
  const { next, sso_error: ssoError } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const target = safeNextPath(next);
  const onSignedIn = useCallback(
    (override?: string) => {
      // New or rotated session: drop anything cached under the previous (or no) session.
      api.clearSession();
      queryClient.clear();
      void navigate({ href: safeNextPath(override ?? target), replace: true });
    },
    [navigate, queryClient, target],
  );
  return <LoginPage next={target} ssoError={ssoError} onSignedIn={onSignedIn} />;
}
