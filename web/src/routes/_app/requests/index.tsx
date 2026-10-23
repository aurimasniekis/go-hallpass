import { createFileRoute, useNavigate } from '@tanstack/react-router';

import { RequestsPage } from '../../../features/requests/RequestsPage';
import { validateRequestSearch } from '../../../features/requests/search';

export const Route = createFileRoute('/_app/requests/')({
  validateSearch: validateRequestSearch,
  component: RequestsRoute,
});

function RequestsRoute() {
  const search = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  return (
    <RequestsPage
      search={search}
      onSearchChange={(next) => {
        void navigate({ search: next, replace: true });
      }}
    />
  );
}
