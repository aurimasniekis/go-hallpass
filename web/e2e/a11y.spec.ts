import { expect, test, type APIRequestContext } from '@playwright/test';

import { expectNoSeriousViolations } from './axe';
import { requireBackend, STORAGE_STATE } from './env';
import { throttle, trackApiRequests } from './throttle';

requireBackend();
test.use({ storageState: STORAGE_STATE });

const STATIC_ROUTES = [
  '/',
  '/requests',
  '/sessions',
  '/activities',
  '/agents',
  '/servers',
  '/groups',
  '/policy',
  '/audit',
  '/operators',
  '/settings/auth',
  '/settings/integrations',
  '/settings/storage',
  '/settings/system',
  '/me',
];

async function firstId(request: APIRequestContext, path: string): Promise<string | null> {
  const res = await request.get(path);
  if (!res.ok()) {
    return null;
  }
  const body = (await res.json()) as { items?: { id?: string }[] };
  return body.items?.[0]?.id ?? null;
}

/** Detail routes for resources that exist on the backend (created by the flow specs). */
async function detailRoutes(request: APIRequestContext): Promise<string[]> {
  const routes: string[] = [];
  const add = async (api: string, ui: (id: string) => string) => {
    const id = await firstId(request, api);
    if (id) {
      routes.push(ui(id));
    }
  };
  await add('/api/v1/agents', (id) => `/agents/${id}`);
  await add('/api/v1/servers', (id) => `/servers/${id}`);
  await add('/api/v1/requests', (id) => `/requests/${id}`);
  await add('/api/v1/access-sessions', (id) => `/sessions/${id}`);
  await add('/api/v1/operators', (id) => `/operators/${id}`);
  const serverId = await firstId(request, '/api/v1/servers');
  if (serverId) {
    await add(`/api/v1/servers/${serverId}/roles`, (id) => `/roles/${id}`);
  }
  return routes;
}

for (const scheme of ['light', 'dark'] as const) {
  test(`every page has no serious axe violations (${scheme})`, async ({ page }) => {
    test.setTimeout(300_000);
    trackApiRequests(page);
    await page.emulateMedia({ colorScheme: scheme });
    const routes = [...STATIC_ROUTES, ...(await detailRoutes(page.request))];
    for (const route of routes) {
      await test.step(route, async () => {
        await throttle();
        await page.goto(route);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        // The page itself must have rendered (not the error boundary, e.g. after a 429).
        await expect(page.getByRole('heading', { level: 1, name: 'Error' })).toHaveCount(0);
        await expect(page.getByText('too many requests')).toHaveCount(0);
        // Let queries settle so the populated state (not only the spinner) is audited. The SSE stream
        // keeps a request open, so "networkidle" never fires; wait for spinners to disappear instead.
        await expect(page.locator('.ant-spin-spinning')).toHaveCount(0, { timeout: 15_000 });
        // Soft: report every page's violations in one run.
        await expectNoSeriousViolations(page, true);
      });
    }
  });
}
