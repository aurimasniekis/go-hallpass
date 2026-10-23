/* eslint-disable no-restricted-imports -- this module is only reachable through the DEV-guarded dynamic import in App.tsx. */
import { TanStackDevtools } from '@tanstack/react-devtools';
import { ReactQueryDevtoolsPanel } from '@tanstack/react-query-devtools';
import { TanStackRouterDevtoolsPanel } from '@tanstack/react-router-devtools';

import type { router as appRouter } from '../router';

export default function Devtools({ router }: { router: typeof appRouter }) {
  return (
    <TanStackDevtools
      plugins={[
        { name: 'TanStack Query', render: <ReactQueryDevtoolsPanel /> },
        { name: 'TanStack Router', render: <TanStackRouterDevtoolsPanel router={router} /> },
      ]}
    />
  );
}
