import { createFileRoute, useNavigate } from '@tanstack/react-router';

import { SERVER_TABS, ServerDetailPage, type ServerTab } from '../../../features/servers/ServerDetailPage';

interface ServerSearch {
  tab?: ServerTab;
}

export const Route = createFileRoute('/_app/servers/$id')({
  validateSearch: (search: Record<string, unknown>): ServerSearch =>
    typeof search.tab === 'string' && (SERVER_TABS as readonly string[]).includes(search.tab)
      ? { tab: search.tab as ServerTab }
      : {},
  component: ServerRoute,
});

function ServerRoute() {
  const { id } = Route.useParams();
  const { tab } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  return (
    <ServerDetailPage
      id={id}
      tab={tab ?? 'overview'}
      onTabChange={(next) => {
        void navigate({ search: next === 'overview' ? {} : { tab: next }, replace: true });
      }}
    />
  );
}
