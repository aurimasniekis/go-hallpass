import { createFileRoute } from '@tanstack/react-router';

import { LoginRoute, validateLoginSearch } from '../features/auth/LoginRoute';

export const Route = createFileRoute('/login')({
  validateSearch: validateLoginSearch,
  component: function Login() {
    return <LoginRoute search={Route.useSearch()} direct />;
  },
});
