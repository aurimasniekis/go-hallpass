import { createFileRoute } from '@tanstack/react-router';

import { LoginRoute, validateLoginSearch } from '../features/auth/LoginRoute';

/** Every sign-in method, never redirected to the default SSO provider: the email and password fallback. */
export const Route = createFileRoute('/login_/password')({
  validateSearch: validateLoginSearch,
  component: function LoginPassword() {
    return <LoginRoute search={Route.useSearch()} direct={false} />;
  },
});
