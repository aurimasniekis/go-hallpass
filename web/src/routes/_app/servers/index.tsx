import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/servers/')({
  component: () => (
    <PlaceholderPage
      title="Servers"
      description="Destination servers and host identities."
      workPackage="WP20"
    />
  ),
});
