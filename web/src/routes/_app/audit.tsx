import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/audit')({
  component: () => (
    <PlaceholderPage title="Audit log" description="Hash-chained audit events." workPackage="WP20" />
  ),
});
