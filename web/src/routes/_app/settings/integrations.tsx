import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/settings/integrations')({
  component: () => (
    <PlaceholderPage
      title="Integrations"
      description="Slack, Telegram and email approvals."
      workPackage="WP20"
    />
  ),
});
