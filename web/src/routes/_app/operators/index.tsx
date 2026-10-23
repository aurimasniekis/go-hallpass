import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/operators/')({
  component: () => (
    <PlaceholderPage
      title="Operators"
      description="Operator accounts, roles and invitations."
      workPackage="WP20"
    />
  ),
});
