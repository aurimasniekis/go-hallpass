import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/settings/system')({
  component: () => <PlaceholderPage title="System" description="Health and lockdown." workPackage="WP20" />,
});
