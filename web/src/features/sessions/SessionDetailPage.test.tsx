import { QueryClientProvider } from '@tanstack/react-query';
import { createMemoryHistory, createRouter, RouterProvider } from '@tanstack/react-router';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { AccessSession, Channel, Grant, Segment, TimelineEvent, TimelinePage } from '../../api/types';
import { ThemeProvider } from '../../ds/theme/ThemeProvider';
import { routeTree } from '../../routeTree.gen';
import { jsonResponse, makeMe } from '../../test/fixtures';
import { createTestQueryClient } from '../../test/utils';
import { enc, page, rec } from './replay/testutil';

// xterm needs a real canvas; the hardened terminal itself is covered by src/ds/terminal.test.ts.
vi.mock('../../ds/TerminalReplay', () => ({
  TerminalReplay: ({ ariaLabel }: { ariaLabel: string }) => <div role="region" aria-label={ariaLabel} />,
}));

class SilentEventSource {
  readyState = 0;
  onopen = null;
  onerror = null;
  addEventListener(): void {
    // no live events
  }
  close(): void {
    this.readyState = 2;
  }
}

const session: AccessSession = {
  id: 's1',
  grant_id: 'g1',
  state: 'open',
  opened_at: '2026-01-01T10:00:00Z',
  closed_at: null,
  agent_id: 'ag1',
  server_id: 'sv1',
  role_id: 'rl1',
  remote_user: 'deploy',
  grant_expires_at: '2099-01-01T00:00:00Z',
  grant_state: 'active',
  retention_class: 'default',
  delete_after: null,
  channels_total: 1,
  channels_live: 0,
};
const channel: Channel = {
  id: 'c1',
  session_id: 's1',
  connection_id: 'cn1',
  agent_id: 'ag1',
  role_id: 'rl1',
  kind: 'exec',
  pty: false,
  state: 'closed',
  opened_at: '2026-01-01T10:00:01Z',
  closed_at: '2026-01-01T10:00:02Z',
  exit_status: 0,
};
const segment: Segment = {
  id: 'seg1',
  session_id: 's1',
  channel_id: 'c1',
  ordinal: 0,
  state: 'interrupted',
  opened_at: '2026-01-01T10:00:01Z',
  finalized_at: null,
  records: 3,
  bytes: 40,
};
const grant: Grant = {
  id: 'g1',
  request_id: 'r1',
  agent_id: 'ag1',
  server_id: 'sv1',
  role_id: 'rl1',
  remote_user: 'deploy',
  capabilities: ['exec'],
  starts_at: '2026-01-01T09:59:00Z',
  expires_at: '2099-01-01T00:00:00Z',
  state: 'active',
  session_id: 's1',
};
const timeline: TimelinePage = {
  items: [
    {
      id: 'e1',
      seq: 1,
      type: 'exec.requested',
      at: '2026-01-01T10:00:01Z',
      channel_id: 'c1',
      data: { bytes: 8 } as unknown as TimelineEvent['data'],
    },
    {
      id: 'e2',
      seq: 2,
      type: 'destination.exec',
      at: '2026-01-01T10:00:02Z',
      data: {
        provenance: 'destination-audit',
        verified: false,
        correlation: 'pid',
        confidence: 'high',
      } as unknown as TimelineEvent['data'],
    },
  ],
  next_after_seq: null,
};

function mockApi(permissions: string[]) {
  const urls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    const url = input instanceof Request ? input.url : input.toString();
    urls.push(url);
    const path = url.split('?')[0];
    const routes: Record<string, unknown> = {
      '/api/v1/me': makeMe({ permissions }),
      '/api/v1/access-sessions/s1': session,
      '/api/v1/access-sessions/s1/channels': { items: [channel] },
      '/api/v1/access-sessions/s1/segments': { items: [segment] },
      '/api/v1/access-sessions/s1/timeline': timeline,
      '/api/v1/access-sessions/s1/destination-records': { items: [] },
      '/api/v1/grants/g1': grant,
      '/api/v1/requests/r1': {
        id: 'r1',
        agent_id: 'ag1',
        server_id: 'sv1',
        role_id: 'rl1',
        requested_duration: 1800,
        state: 'approved',
        policy_version: 1,
        created_at: '2026-01-01T09:58:00Z',
        expires_at: '2026-01-01T10:08:00Z',
        has_reason: true,
        reason: 'deploy‮fix',
      },
      '/api/v1/recordings/seg1/records': page(
        [
          rec(1, 'exec.requested@1', enc('uname -a'), 0, 'meta'),
          rec(2, 'stdout@1', enc('Linux\n'), 10, 'stdout'),
          rec(3, 'exit@1', [0, 0], 20, 'meta'),
        ],
        false,
        { complete: false, incomplete: true },
      ),
    };
    const body = path !== undefined ? routes[path] : undefined;
    return body !== undefined
      ? Promise.resolve(jsonResponse(200, body))
      : Promise.reject(new Error(`unexpected ${url}`));
  });
  return urls;
}

function renderAt(path: string) {
  const queryClient = createTestQueryClient();
  const router = createRouter({
    routeTree,
    context: { queryClient },
    history: createMemoryHistory({ initialEntries: [path] }),
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ThemeProvider mode="light">
        <RouterProvider router={router} />
      </ThemeProvider>
    </QueryClientProvider>,
  );
}

describe('<SessionDetailPage>', () => {
  beforeEach(() => {
    vi.stubGlobal('EventSource', SilentEventSource);
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('shows summary, grant, untrusted reason, integrity warning, timeline provenance', async () => {
    mockApi(['sessions.read', 'requests.read', 'requests.reason.read', 'grants.revoke']);
    renderAt('/sessions/s1');
    expect(await screen.findByRole('heading', { level: 1, name: 'Access session' })).toBeInTheDocument();
    expect(await screen.findByText('Recording integrity warning')).toBeInTheDocument();
    // Reason is agent-provided: rendered through UntrustedText with the bidi override revealed.
    const marker = await screen.findByText('<U+202E>');
    expect(marker.closest('[data-untrusted="true"]')?.textContent).toContain('deployfix'.slice(0, 6));
    expect(screen.getByRole('button', { name: 'Revoke grant g1' })).toBeInTheDocument();
    const tl = await screen.findByRole('list', { name: 'Session timeline' });
    expect(within(tl).getByText('Captured')).toBeInTheDocument();
    expect(within(tl).getByText('Destination-reported, unverified')).toBeInTheDocument();
    // The always-false "verified" field is not displayed.
    expect(within(tl).queryByText('verified')).not.toBeInTheDocument();
    expect(screen.getByText('Replay needs the recording.play permission')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Export/ })).not.toBeInTheDocument();
  });

  it('replays an exec channel on demand: captured command, separate stdout/stderr, incomplete banner', async () => {
    const user = userEvent.setup();
    const urls = mockApi(['sessions.read', 'recording.play', 'recording.export']);
    renderAt('/sessions/s1');
    const load = await screen.findByRole('button', { name: 'Load recording' });
    // Nothing is decrypted (or audited) until the operator asks.
    expect(urls.some((u) => u.includes('/recordings/'))).toBe(false);
    await user.click(load);
    expect(await screen.findByText('Incomplete (interrupted)')).toBeInTheDocument();
    expect(urls).toContain('/api/v1/recordings/seg1/records?from_seq=0');
    expect(screen.getByText('uname -a')).toBeInTheDocument();
    expect(screen.getAllByText('Captured').length).toBeGreaterThan(0);
    expect(screen.getByRole('region', { name: 'Standard output replay' })).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Standard error replay' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Play/ })).toBeEnabled();
    expect(screen.getByRole('button', { name: /Export encrypted bundle/ })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Export decrypted/ })).toBeInTheDocument();
    await waitFor(() => {
      expect(document.body.textContent).not.toMatch(/(?<!un)(?<!not )verified/i);
    });
  });
});
