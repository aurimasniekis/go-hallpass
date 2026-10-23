import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, useNavigate } from '@tanstack/react-router';

import { api } from '../api/client';
import { safeNextPath } from '../features/auth/redirect';
import { LoginPage } from '../features/auth/LoginPage';

interface LoginSearch {
  next?: string;
}

export const Route = createFileRoute('/login')({
  validateSearch: (search: Record<string, unknown>): LoginSearch =>
    typeof search.next === 'string' ? { next: search.next } : {},
  component: LoginRoute,
});

function LoginRoute() {
  const { next } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const target = safeNextPath(next);
  return (
    <LoginPage
      next={target}
      onSignedIn={() => {
        // New session: drop anything cached under the previous (or no) session.
        api.clearSession();
        queryClient.clear();
        void navigate({ href: target, replace: true });
      }}
    />
  );
}
