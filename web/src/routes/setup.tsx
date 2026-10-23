import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { SetupPage } from '../features/auth/SetupPage';

interface SetupSearch {
  token?: string;
}

export const Route = createFileRoute('/setup')({
  validateSearch: (search: Record<string, unknown>): SetupSearch =>
    typeof search.token === 'string' ? { token: search.token } : {},
  component: SetupRoute,
});

function SetupRoute() {
  const { token } = Route.useSearch();
  const navigate = useNavigate();
  // Keep the one-time token in memory only and remove it from the address bar and history entry.
  const [initialToken] = useState(token ?? '');
  useEffect(() => {
    if (token !== undefined) {
      void navigate({ to: '/setup', search: {}, replace: true });
    }
  }, [navigate, token]);
  return (
    <SetupPage
      initialToken={initialToken}
      onDone={() => {
        void navigate({ to: '/login' });
      }}
    />
  );
}
