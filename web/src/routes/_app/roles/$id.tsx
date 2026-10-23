import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/roles/$id')({
  component: () => (
    <PlaceholderPage
      title="Role"
      description="Server role, login binding and credentials."
      workPackage="WP20"
    />
  ),
});
