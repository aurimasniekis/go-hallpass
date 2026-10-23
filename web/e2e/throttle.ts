import type { Page } from '@playwright/test';

/**
 * The backend rate-limits API requests (300/min per IP, 600/min per session; internal/httpapi). Every
 * full page load re-fetches /me and refreshes all active queries when the live-event stream opens, so a
 * page sweep can exhaust the budget. Specs record their API requests here and wait before a burst would
 * cross `budget` requests in the last minute. One worker runs all specs, so the window is shared.
 */
const sent: number[] = [];

export function trackApiRequests(page: Page): void {
  page.on('request', (req) => {
    if (new URL(req.url()).pathname.startsWith('/api/')) {
      sent.push(Date.now());
    }
  });
}

export async function throttle(budget = 200): Promise<void> {
  for (;;) {
    const cutoff = Date.now() - 60_000;
    while (sent.length > 0 && (sent[0] ?? 0) < cutoff) {
      sent.shift();
    }
    if (sent.length < budget) {
      return;
    }
    await new Promise((r) => setTimeout(r, 1_000));
  }
}
