import { useQueryClient } from '@tanstack/react-query';
import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { RecoverPage } from '../features/auth/RecoverPage';

interface RecoverSearch {
  token?: string;
}

export const Route = createFileRoute('/recover')({
  validateSearch: (search: Record<string, unknown>): RecoverSearch =>
    typeof search.token === 'string' ? { token: search.token } : {},
  component: RecoverRoute,
});

function RecoverRoute() {
  const { token } = Route.useSearch();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  // Keep the single-use token in memory only and remove it from the address bar and history entry.
  const [initialToken] = useState(token ?? '');
  useEffect(() => {
    if (token !== undefined) {
      void navigate({ to: '/recover', search: {}, replace: true });
    }
  }, [navigate, token]);
  return (
    <RecoverPage
      initialToken={initialToken}
      onDone={() => {
        // New session: drop anything cached under the previous (or no) session.
        queryClient.clear();
        void navigate({ to: '/' });
      }}
      onResetPassword={(url) => {
        if (url.startsWith('/reset/')) {
          void navigate({ href: url });
        }
      }}
    />
  );
}
