import type { QueryClient } from '@tanstack/react-query';
import { createRootRouteWithContext, Link, Outlet } from '@tanstack/react-router';
import { Result } from 'antd';

import { ErrorState } from '../ds/states';

export interface RouterContext {
  queryClient: QueryClient;
}

export const Route = createRootRouteWithContext<RouterContext>()({
  component: Outlet,
  notFoundComponent: NotFound,
  errorComponent: ({ error, reset }) => (
    <main className="hp-shell-content">
      <h1 className="hp-visually-hidden">Error</h1>
      <ErrorState error={error} title="Something went wrong" onRetry={reset} />
    </main>
  ),
});

function NotFound() {
  return (
    <main className="hp-shell-content">
      <h1 className="hp-visually-hidden">Page not found</h1>
      <Result status="404" title="Page not found" extra={<Link to="/">Go to dashboard</Link>} />
    </main>
  );
}
