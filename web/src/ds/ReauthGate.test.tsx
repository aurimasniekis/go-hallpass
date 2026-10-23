import { screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { ApiClient } from '../api/client';
import { renderWithProviders } from '../test/utils';
import { ReauthGate } from './ReauthGate';

function json(status: number, body: unknown, type = 'application/json') {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': type } });
}

describe('<ReauthGate>', () => {
  it('prompts on reauth_required, posts the password, then retries the original request', async () => {
    const user = userEvent.setup();
    const seen: { url: string; body: unknown }[] = [];
    const responses = [
      () =>
        json(
          401,
          { code: 'reauth_required', status: 401, detail: 'Reauthentication required' },
          'application/problem+json',
        ),
      () => new Response(null, { status: 204 }),
      () =>
        json(200, {
          operator_id: 'op',
          display_name: 'Op',
          roles: [],
          permissions: [],
          csrf_token: 'rotated',
          auth_time: '2026-01-01T00:00:00Z',
        }),
      () => json(200, { done: true }),
    ];
    const client = new ApiClient({
      fetch: (input, init) => {
        seen.push({ url: input instanceof Request ? input.url : input.toString(), body: init?.body });
        const next = responses.shift();
        if (!next) {
          throw new Error('unexpected request');
        }
        return Promise.resolve(next());
      },
    });
    client.setCsrfToken('initial');
    renderWithProviders(<ReauthGate client={client} />);

    const pending = client.post('/system/lockdown');
    const password = await screen.findByLabelText('Password');
    await user.type(password, 'correct horse battery');
    await user.click(screen.getByRole('button', { name: 'Verify' }));

    await expect(pending).resolves.toEqual({ done: true });
    expect(seen.map((s) => s.url)).toEqual([
      '/api/v1/system/lockdown',
      '/api/v1/auth/reauth',
      '/api/v1/me',
      '/api/v1/system/lockdown',
    ]);
    expect(JSON.parse(String(seen[1]?.body))).toEqual({ password: 'correct horse battery' });
  });

  it('rejects the original request when the operator cancels', async () => {
    const user = userEvent.setup();
    const client = new ApiClient({
      fetch: () =>
        Promise.resolve(
          json(
            401,
            { code: 'reauth_required', status: 401, detail: 'Reauthentication required' },
            'application/problem+json',
          ),
        ),
    });
    client.setCsrfToken('t');
    renderWithProviders(<ReauthGate client={client} />);
    const outcome = client.post('/x').catch((e: unknown) => e);
    await user.click(await screen.findByRole('button', { name: 'Cancel' }));
    await expect(outcome).resolves.toMatchObject({ code: 'reauth_required' });
  });
});
