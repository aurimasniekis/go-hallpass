import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/agents/')({
  component: () => (
    <PlaceholderPage title="Agents" description="Registered agents and their keys." workPackage="WP20" />
  ),
});
