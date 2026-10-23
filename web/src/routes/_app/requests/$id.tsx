import { createFileRoute } from '@tanstack/react-router';

import { RequestDetailPage } from '../../../features/requests/RequestDetailPage';

export const Route = createFileRoute('/_app/requests/$id')({
  component: RequestDetailRoute,
});

function RequestDetailRoute() {
  const { id } = Route.useParams();
  return <RequestDetailPage id={id} />;
}
