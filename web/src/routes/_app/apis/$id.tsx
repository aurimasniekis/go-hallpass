import { createFileRoute } from '@tanstack/react-router';

import { ApiTargetDetailPage } from '../../../features/apis/ApiTargetDetailPage';

export const Route = createFileRoute('/_app/apis/$id')({
  component: ApiTargetRoute,
});

function ApiTargetRoute() {
  const { id } = Route.useParams();
  return <ApiTargetDetailPage id={id} />;
}
