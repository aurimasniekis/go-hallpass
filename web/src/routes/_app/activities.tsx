import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/activities')({
  component: () => (
    <PlaceholderPage
      title="Activities"
      description="Live channels across active sessions."
      workPackage="WP20"
    />
  ),
});
