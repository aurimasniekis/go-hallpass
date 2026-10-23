import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/sessions/$id')({
  component: () => (
    <PlaceholderPage title="Session" description="Session summary, timeline and replay." workPackage="WP21" />
  ),
});
