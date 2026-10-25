import { createFileRoute } from '@tanstack/react-router';

import { BackupsPage } from '../../../features/settings/BackupsPage';

export const Route = createFileRoute('/_app/settings/backups')({
  component: BackupsPage,
});
