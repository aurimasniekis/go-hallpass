import { createFileRoute } from '@tanstack/react-router';

import { OperatorsPage } from '../../../features/operators/OperatorsPage';

export const Route = createFileRoute('/_app/operators/')({
  component: OperatorsPage,
});
