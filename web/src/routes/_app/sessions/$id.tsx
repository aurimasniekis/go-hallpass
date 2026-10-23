import { createFileRoute } from '@tanstack/react-router';

import { SessionDetailPage } from '../../../features/sessions/SessionDetailPage';

export const Route = createFileRoute('/_app/sessions/$id')({
  component: SessionRoute,
});

function SessionRoute() {
  const { id } = Route.useParams();
  return <SessionDetailPage id={id} />;
}
