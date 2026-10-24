import { randomUUID } from 'node:crypto';

import type { Page } from '@playwright/test';

import { e2eUrl } from './env';
import { noteApiRequest, throttle } from './throttle';

/** Same-origin API calls with the signed-in browser session (CSRF, Origin and idempotency headers). */
export class Api {
  private csrf = '';
  constructor(private readonly page: Page) {}

  async init(): Promise<void> {
    this.csrf = (await this.call<{ csrf_token: string }>('GET', '/api/v1/me')).csrf_token;
  }

  async call<T>(method: string, path: string, data?: unknown): Promise<T> {
    await throttle(220);
    noteApiRequest();
    const res = await this.page.request.fetch(path, {
      method,
      ...(data === undefined ? {} : { data }),
      headers: { Origin: e2eUrl ?? '', 'X-CSRF-Token': this.csrf, 'Idempotency-Key': randomUUID() },
    });
    if (!res.ok()) {
      throw new Error(`${method} ${path}: ${String(res.status())} ${await res.text()}`);
    }
    return (res.status() === 204 ? undefined : await res.json()) as T;
  }
}
