import { createFileRoute } from '@tanstack/react-router';

import { ApiTargetsPage } from '../../../features/apis/ApiTargetsPage';

export const Route = createFileRoute('/_app/apis/')({
  component: ApiTargetsPage,
});
