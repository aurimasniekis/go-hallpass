import { createFileRoute } from '@tanstack/react-router';

import { AgentDetailPage } from '../../../features/agents/AgentDetailPage';

export const Route = createFileRoute('/_app/agents/$id')({
  component: AgentRoute,
});

function AgentRoute() {
  const { id } = Route.useParams();
  return <AgentDetailPage id={id} />;
}
