import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/policy')({
  component: () => (
    <PlaceholderPage
      title="Policy"
      description="Access rules, approver rules and preview."
      workPackage="WP20"
    />
  ),
});
