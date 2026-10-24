import { createFileRoute } from '@tanstack/react-router';

import { GitRemoteDetailPage } from '../../../features/git/GitRemoteDetailPage';

export const Route = createFileRoute('/_app/git/$id')({
  component: GitRoute,
});

function GitRoute() {
  const { id } = Route.useParams();
  return <GitRemoteDetailPage id={id} />;
}
