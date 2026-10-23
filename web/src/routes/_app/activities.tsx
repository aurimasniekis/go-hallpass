import { createFileRoute } from '@tanstack/react-router';

import { ActivitiesPage } from '../../features/activities/ActivitiesPage';

export const Route = createFileRoute('/_app/activities')({
  component: ActivitiesPage,
});
