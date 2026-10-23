import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/servers/$id')({
  component: () => (
    <PlaceholderPage
      title="Server"
      description="Host identities, roles and credentials."
      workPackage="WP20"
    />
  ),
});
