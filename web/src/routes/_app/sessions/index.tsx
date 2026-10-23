import { createFileRoute, useNavigate } from '@tanstack/react-router';

import { validateSessionsSearch } from '../../../features/sessions/search';
import { SessionsPage } from '../../../features/sessions/SessionsPage';

export const Route = createFileRoute('/_app/sessions/')({
  validateSearch: validateSessionsSearch,
  component: SessionsRoute,
});

function SessionsRoute() {
  const search = Route.useSearch();
  const navigate = useNavigate();
  return (
    <SessionsPage
      search={search}
      onSearchChange={(next) => {
        void navigate({ to: '/sessions', search: next, replace: true });
      }}
    />
  );
}
