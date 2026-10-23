import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/requests/')({
  component: () => (
    <PlaceholderPage
      title="Requests"
      description="Access requests from agents awaiting or past decision."
      workPackage="WP20"
    />
  ),
});
