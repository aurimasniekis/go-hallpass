import { createFileRoute } from '@tanstack/react-router';

import { OperatorDetailPage } from '../../../features/operators/OperatorDetailPage';

export const Route = createFileRoute('/_app/operators/$id')({
  component: OperatorRoute,
});

function OperatorRoute() {
  const { id } = Route.useParams();
  return <OperatorDetailPage id={id} />;
}
