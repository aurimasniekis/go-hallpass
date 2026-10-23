import { createFileRoute } from '@tanstack/react-router';

import { StoragePage } from '../../../features/settings/StoragePage';

export const Route = createFileRoute('/_app/settings/storage')({
  component: StoragePage,
});
