import { createFileRoute, useNavigate } from '@tanstack/react-router';

import { AuthSettingsPage } from '../../../features/settings/AuthSettingsPage';

interface AuthSettingsSearch {
  /** Set by the OIDC callback after a test login (`/settings/auth?test_login=<provider_id>`). */
  test_login?: string;
}

export const Route = createFileRoute('/_app/settings/auth')({
  validateSearch: (search: Record<string, unknown>): AuthSettingsSearch =>
    typeof search.test_login === 'string' && /^[A-Za-z0-9_.-]{1,64}$/.test(search.test_login)
      ? { test_login: search.test_login }
      : {},
  component: AuthSettingsRoute,
});

function AuthSettingsRoute() {
  const { test_login: testLogin } = Route.useSearch();
  const navigate = useNavigate();
  return (
    <AuthSettingsPage
      testLoginProviderId={testLogin}
      onClearTestLogin={() => {
        void navigate({ to: '/settings/auth', search: {}, replace: true });
      }}
    />
  );
}
