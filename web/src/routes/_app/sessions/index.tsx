import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/sessions/')({
  component: () => (
    <PlaceholderPage
      title="Sessions"
      description="Access sessions created by approved grants."
      workPackage="WP20"
    />
  ),
});
