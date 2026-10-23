import { createFileRoute } from '@tanstack/react-router';

import { RoleDetailPage } from '../../../features/roles/RoleDetailPage';

export const Route = createFileRoute('/_app/roles/$id')({
  component: RoleRoute,
});

function RoleRoute() {
  const { id } = Route.useParams();
  return <RoleDetailPage id={id} />;
}
