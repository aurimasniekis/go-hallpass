import { createFileRoute } from '@tanstack/react-router';

import { PolicyPage } from '../../features/policy/PolicyPage';

export const Route = createFileRoute('/_app/policy')({
  component: PolicyPage,
});
