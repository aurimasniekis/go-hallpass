import { createFileRoute } from '@tanstack/react-router';

import { ApiTokensPage } from '../../../features/settings/ApiTokensPage';

export const Route = createFileRoute('/_app/settings/api-tokens')({
  component: ApiTokensPage,
});
