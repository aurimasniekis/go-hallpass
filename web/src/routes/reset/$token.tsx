import { createFileRoute, useNavigate } from '@tanstack/react-router';
import { useEffect, useState } from 'react';

import { ResetPasswordPage } from '../../features/auth/TokenPages';

export const Route = createFileRoute('/reset/$token')({
  component: ResetRoute,
});

function ResetRoute() {
  const { token } = Route.useParams();
  const navigate = useNavigate();
  // Keep the single-use token in memory only and drop it from the address bar and history entry.
  const [held] = useState(token);
  useEffect(() => {
    window.history.replaceState(window.history.state, '', '/reset/redeemed');
  }, []);
  return (
    <ResetPasswordPage
      token={held === 'redeemed' ? '' : held}
      onSignIn={() => {
        void navigate({ to: '/login' });
      }}
    />
  );
}
