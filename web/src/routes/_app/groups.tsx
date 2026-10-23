import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/groups')({
  component: () => (
    <PlaceholderPage title="Groups" description="Agent and server groups." workPackage="WP20" />
  ),
});
