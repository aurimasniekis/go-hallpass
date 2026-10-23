import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/operators/$id')({
  component: () => (
    <PlaceholderPage title="Operator" description="Operator roles, sessions and audit." workPackage="WP20" />
  ),
});
