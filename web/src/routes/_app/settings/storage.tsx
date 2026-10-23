import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/settings/storage')({
  component: () => (
    <PlaceholderPage
      title="Storage & keys"
      description="Retention, storage usage and key status."
      workPackage="WP20"
    />
  ),
});
