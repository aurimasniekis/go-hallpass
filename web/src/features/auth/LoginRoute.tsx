import { useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { useCallback } from 'react';

import { api } from '../../api/client';
import { LoginPage } from './LoginPage';
import { safeNextPath } from './redirect';

export interface LoginSearch {
  next?: string;
  /** Stable error code from a failed SSO flow (`/login?sso_error=<code>`). */
  sso_error?: string;
}

export function validateLoginSearch(search: Record<string, unknown>): LoginSearch {
  return {
    ...(typeof search.next === 'string' ? { next: search.next } : {}),
    ...(typeof search.sso_error === 'string' && /^[a-z0-9_.-]{1,64}$/.test(search.sso_error)
      ? { sso_error: search.sso_error }
      : {}),
  };
}

/** The sign-in page for `/login` (`direct`: may continue to the default SSO provider) and `/login/password`. */
export function LoginRoute({ search, direct }: { search: LoginSearch; direct: boolean }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const target = safeNextPath(search.next);
  const onSignedIn = useCallback(
    (override?: string) => {
      // New or rotated session: drop anything cached under the previous (or no) session.
      api.clearSession();
      queryClient.clear();
      void navigate({ href: safeNextPath(override ?? target), replace: true });
    },
    [navigate, queryClient, target],
  );
  return <LoginPage next={target} ssoError={search.sso_error} onSignedIn={onSignedIn} direct={direct} />;
}
