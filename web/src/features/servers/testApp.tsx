import { QueryClientProvider } from '@tanstack/react-query';
import {
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
  useParams,
  useSearch,
} from '@tanstack/react-router';
import { render } from '@testing-library/react';
import { App } from 'antd';
import { vi } from 'vitest';

import type { router as appRouter } from '../../router';
import { ThemeProvider } from '../../ds/theme/ThemeProvider';
import { jsonResponse, makeMe } from '../../test/fixtures';
import { createTestQueryClient } from '../../test/utils';
import { AgentDetailPage } from '../agents/AgentDetailPage';
import { AgentsPage } from '../agents/AgentsPage';
import { GitRemoteDetailPage } from '../git/GitRemoteDetailPage';
import { GitRemotesPage } from '../git/GitRemotesPage';
import { GroupsPage } from '../groups/GroupsPage';
import { RoleDetailPage } from '../roles/RoleDetailPage';
import { SERVER_TABS, ServerDetailPage } from './ServerDetailPage';
import { ServersPage } from './ServersPage';

/**
 * Test harness for the inventory pages: a small router with only these pages (so other features are not
 * loaded) and a scripted global fetch. Every request is recorded; unscripted requests fail the test.
 */
export interface RecordedCall {
  method: string;
  url: string;
  body: unknown;
  headers: Headers;
}

export type Handler = readonly [
  method: string,
  path: string | RegExp,
  respond: (call: RecordedCall) => Response,
];

type AppRouter = typeof appRouter;

export function renderInventory(path: string, opts: { permissions: string[]; handlers: readonly Handler[] }) {
  const calls: RecordedCall[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const method = init?.method ?? 'GET';
    const call: RecordedCall = {
      method,
      url,
      body: typeof init?.body === 'string' ? (JSON.parse(init.body) as unknown) : undefined,
      headers: new Headers(init?.headers),
    };
    calls.push(call);
    if (method === 'GET' && url === '/api/v1/me') {
      return Promise.resolve(jsonResponse(200, makeMe({ permissions: opts.permissions })));
    }
    const pathOnly = url.split('?')[0] ?? url;
    const h = opts.handlers.find(
      ([m, p]) => m === method && (typeof p === 'string' ? p === pathOnly : p.test(url)),
    );
    if (!h) {
      return Promise.reject(new Error(`unscripted request ${method} ${url}`));
    }
    return Promise.resolve(h[2](call));
  });

  const root = createRootRoute({ component: Outlet });
  const routes = [
    createRoute({ getParentRoute: () => root, path: '/agents', component: AgentsPage }),
    createRoute({ getParentRoute: () => root, path: '/agents/$id', component: AgentRoute }),
    createRoute({ getParentRoute: () => root, path: '/servers', component: ServersPage }),
    createRoute({
      getParentRoute: () => root,
      path: '/servers/$id',
      validateSearch: (s: Record<string, unknown>) => (typeof s.tab === 'string' ? { tab: s.tab } : {}),
      component: ServerRoute,
    }),
    createRoute({ getParentRoute: () => root, path: '/roles/$id', component: RoleRoute }),
    createRoute({ getParentRoute: () => root, path: '/git', component: GitRemotesPage }),
    createRoute({ getParentRoute: () => root, path: '/git/$id', component: GitRoute }),
    // Link target only (operator names link here); the page itself is not under test.
    createRoute({ getParentRoute: () => root, path: '/operators/$id', component: () => null }),
    createRoute({
      getParentRoute: () => root,
      path: '/groups',
      validateSearch: (s: Record<string, unknown>) => (typeof s.kind === 'string' ? { kind: s.kind } : {}),
      component: GroupsRoute,
    }),
  ];
  const queryClient = createTestQueryClient();
  const router = createRouter({
    routeTree: root.addChildren(routes),
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider mode="light">
        <App>
          <RouterProvider router={router as unknown as AppRouter} />
        </App>
      </ThemeProvider>
    </QueryClientProvider>,
  );
  return { calls, router, queryClient };
}

export const ts = '2026-06-01T10:00:00Z';

function AgentRoute() {
  const { id } = useParams({ strict: false });
  return <AgentDetailPage id={id ?? ''} />;
}

function ServerRoute() {
  const { id } = useParams({ strict: false });
  const { tab } = useSearch({ strict: false });
  const serverTab = SERVER_TABS.find((t) => t === tab) ?? 'overview';
  return <ServerDetailPage id={id ?? ''} tab={serverTab} />;
}

function GitRoute() {
  const { id } = useParams({ strict: false });
  return <GitRemoteDetailPage id={id ?? ''} />;
}

function RoleRoute() {
  const { id } = useParams({ strict: false });
  return <RoleDetailPage id={id ?? ''} />;
}

function GroupsRoute() {
  const { kind } = useSearch({ strict: false });
  return <GroupsPage {...(kind ? { kind } : {})} onKindChange={() => undefined} />;
}
