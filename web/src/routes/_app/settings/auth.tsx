import { createFileRoute } from '@tanstack/react-router';

import { PlaceholderPage } from '../../../features/placeholder/PlaceholderPage';

export const Route = createFileRoute('/_app/settings/auth')({
  component: () => (
    <PlaceholderPage
      title="Authentication"
      description="Login methods, password and MFA policy, OIDC providers."
      workPackage="WP20"
    />
  ),
});
