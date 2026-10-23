import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/requests/$id')({
  component: () => (
    <PlaceholderPage
      title="Request"
      description="Request detail, decision and audit trail."
      workPackage="WP20"
    />
  ),
});
