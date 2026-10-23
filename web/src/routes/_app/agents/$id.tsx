import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/agents/$id')({
  component: () => (
    <PlaceholderPage
      title="Agent"
      description="Keys, groups, labels, effective access and audit."
      workPackage="WP20"
    />
  ),
});
