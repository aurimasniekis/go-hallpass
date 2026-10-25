import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { jsonResponse, makeMe, problemResponse } from '../../test/fixtures';
import { mockApi } from '../policy/mockApi';
import { renderInRouter } from '../requests/testHelpers';
import { BackupsPage } from './BackupsPage';

const target = {
  enabled: true,
  endpoint: 'https://s3.eu-central-1.amazonaws.com',
  region: 'eu-central-1',
  bucket: 'acme-backups',
  prefix: 'hallpass/',
  path_style: false,
  access_key_id: 'AKIAEXAMPLE',
  allow_private_network: false,
  interval: '1h0m0s',
  keep_last: 48,
  keep_daily_days: 30,
  version: 3,
  created_at: '2026-10-25T08:00:00Z',
  updated_at: '2026-10-25T08:00:00Z',
};

const run = {
  id: 'bkp_1',
  trigger: 'schedule',
  state: 'succeeded',
  started_at: '2026-10-25T09:00:00Z',
  finished_at: '2026-10-25T09:00:12Z',
  db_bytes: 2_000_000,
  segments: 12,
  segments_uploaded: 2,
  uploaded_bytes: 4_000_000,
  stored: true,
};

const admin = makeMe({
  permissions: ['system.read', 'system.settings'],
  operator: { roles: ['administrator'] },
});

describe('<BackupsPage>', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('sets up a target with the secret sent once', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': admin,
      'GET /api/v1/system/backups': { configured: false, enabled: false, running: false },
      'GET /api/v1/system/backups/target': () =>
        problemResponse(404, 'not_found', 'no backup target is configured'),
      'GET /api/v1/system/backups/runs': { items: [], next_cursor: null },
      'PUT /api/v1/system/backups/target': () => jsonResponse(200, target),
    });
    renderInRouter(<BackupsPage />);
    await user.click(await screen.findByRole('button', { name: 'Set up backups' }));
    const form = await screen.findByRole('form', { name: 'Backup target' });
    await user.type(within(form).getByLabelText('Endpoint'), target.endpoint);
    await user.clear(within(form).getByLabelText('Region'));
    await user.type(within(form).getByLabelText('Region'), 'eu-central-1');
    await user.type(within(form).getByLabelText('Bucket'), 'acme-backups');
    await user.type(within(form).getByLabelText('Access key ID'), 'AKIAEXAMPLE');
    await user.type(within(form).getByLabelText('Secret access key'), 'wJalrXUtnFEMI');
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PUT')).toBe(true);
    });
    const put = calls.find((c) => c.method === 'PUT');
    expect(put?.body).toMatchObject({
      endpoint: target.endpoint,
      region: 'eu-central-1',
      bucket: 'acme-backups',
      prefix: 'hallpass/',
      access_key_id: 'AKIAEXAMPLE',
      secret_access_key: 'wJalrXUtnFEMI',
      interval: '1h',
      keep_last: 48,
      keep_daily_days: 30,
      enabled: true,
    });
    expect(put?.headers.get('If-Match')).toBeNull();
  });

  it('shows the target and runs, edits with If-Match and keeps the secret, and backs up now', async () => {
    const user = userEvent.setup();
    const { calls } = mockApi({
      'GET /api/v1/me': admin,
      'GET /api/v1/system/backups': {
        configured: true,
        enabled: true,
        running: false,
        last_run: run,
        last_success: run,
        next_run_at: '2026-10-25T10:00:00Z',
      },
      'GET /api/v1/system/backups/target': target,
      'GET /api/v1/system/backups/runs': { items: [run], next_cursor: null },
      'PUT /api/v1/system/backups/target': () => jsonResponse(200, { ...target, version: 4 }),
      'POST /api/v1/system/backups/runs': () =>
        jsonResponse(202, { ...run, id: 'bkp_2', state: 'running', trigger: 'manual' }),
    });
    renderInRouter(<BackupsPage />);
    expect(await screen.findByText('acme-backups/hallpass/')).toBeInTheDocument();
    expect(screen.getByText('Every 1h')).toBeInTheDocument();
    expect(screen.getByText('The newest 48, plus one per day for 30 days')).toBeInTheDocument();
    expect(await screen.findByText('12 (2 new)')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Edit target/ }));
    const form = await screen.findByRole('form', { name: 'Backup target' });
    expect(within(form).getByText('Leave empty to keep the stored key.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'PUT')).toBe(true);
    });
    const put = calls.find((c) => c.method === 'PUT');
    expect(put?.headers.get('If-Match')).toBe('"3"');
    expect(put?.body).not.toHaveProperty('secret_access_key');

    await user.click(screen.getByRole('button', { name: /Back up now/ }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'POST' && c.path === '/api/v1/system/backups/runs')).toBe(true);
    });
  });

  it('is read-only without system.settings', async () => {
    mockApi({
      'GET /api/v1/me': makeMe({ permissions: ['system.read'] }),
      'GET /api/v1/system/backups': { configured: true, enabled: true, running: false },
      'GET /api/v1/system/backups/target': target,
      'GET /api/v1/system/backups/runs': { items: [run], next_cursor: null },
    });
    renderInRouter(<BackupsPage />);
    expect(await screen.findByText('acme-backups/hallpass/')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Back up now/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Edit target/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Test connection' })).not.toBeInTheDocument();
  });
});
