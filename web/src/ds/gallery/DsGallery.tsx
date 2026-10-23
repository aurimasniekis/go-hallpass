import { Button, Card, Space, Typography } from 'antd';
import { useState, type ReactNode } from 'react';

import { ApiClient } from '../../api/client';
import { ApiError } from '../../api/errors';
import { ChartCard } from '../ChartCard';
import { ConfirmAction } from '../ConfirmAction';
import { ConnectionBanner } from '../ConnectionBanner';
import { CopyField } from '../CopyField';
import { Countdown } from '../Countdown';
import { DataTable, type SortState } from '../DataTable';
import { Fingerprint } from '../Fingerprint';
import { KeyValueGrid } from '../KeyValueGrid';
import { PageHeader } from '../PageHeader';
import { PermissionGate } from '../PermissionGate';
import { ReauthGate } from '../ReauthGate';
import { EmptyState, ErrorState, LoadingState, NotImplemented, PermissionDenied } from '../states';
import { StatusBadge } from '../StatusBadge';
import { TerminalReplay } from '../TerminalReplay';
import { ThemeProvider } from '../theme/ThemeProvider';
import type { ResolvedTheme } from '../theme/tokens';
import { UntrustedText } from '../UntrustedText';

/**
 * DEV-ONLY design-system gallery (docs/PLAN.md §14.2, HP-UI-015 visual snapshots).
 * Everything here is clearly-labelled fixture input for rendering components; it is never reachable
 * in production builds (see routes/[__ds].tsx) and must not be reused as product data.
 */

interface FixtureRow {
  id: string;
  name: string;
  state: string;
}

const FIXTURE_ROWS: FixtureRow[] = [
  { id: 'fx-1', name: 'fixture-agent-a', state: 'active' },
  { id: 'fx-2', name: 'fixture-agent-b', state: 'disabled' },
];

const FIXTURE_COLUMNS = [
  { key: 'name', dataIndex: 'name', title: 'Name', sorter: true },
  {
    key: 'state',
    dataIndex: 'state',
    title: 'State',
    render: (v: string) => <StatusBadge tone={v === 'active' ? 'success' : 'neutral'}>{v}</StatusBadge>,
  },
];

const HOSTILE_OUTPUT = [
  '\x1b[1;32m$\x1b[0m uname -a\r\n',
  'Linux fixture 6.8.0 x86_64 GNU/Linux\r\n',
  '\x1b]0;title-change-attempt\x07\x1b]8;;https://example.invalid\x07hyperlink-attempt\x1b]8;;\x07\r\n',
  '\x1b]52;c;Zml4dHVyZQ==\x07clipboard write attempt swallowed\r\n',
];

/** Offline client whose first call needs reauth, so the ReauthGate can be exercised in the gallery. */
function createReauthDemoClient(): ApiClient {
  {
    let calls = 0;
    const client = new ApiClient({
      fetch: () => {
        calls += 1;
        if (calls === 1) {
          return Promise.resolve(
            new Response(
              JSON.stringify({ status: 401, code: 'reauth_required', detail: 'Reauthentication required' }),
              {
                status: 401,
                headers: { 'Content-Type': 'application/problem+json' },
              },
            ),
          );
        }
        if (calls === 3) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                operator_id: 'fixture',
                display_name: 'Fixture',
                roles: [],
                permissions: [],
                csrf_token: 'fixture',
                auth_time: new Date().toISOString(),
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            ),
          );
        }
        if (calls > 4) {
          calls = 0;
        }
        return Promise.resolve(new Response(null, { status: 204 }));
      },
    });
    client.setCsrfToken('fixture');
    return client;
  }
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function GalleryPane({ mode }: { mode: ResolvedTheme }) {
  const [sort, setSort] = useState<SortState | null>({ field: 'name', order: 'ascend' });
  const [deadline] = useState(() => new Date(Date.now() + 5 * 60_000 + 7_000).toISOString());
  const [urgentDeadline] = useState(() => new Date(Date.now() + 42_000).toISOString());
  const [reauthClient] = useState(createReauthDemoClient);
  const [reauthResult, setReauthResult] = useState<string>('not run');

  return (
    <div className="hp-gallery__pane" data-gallery-theme={mode}>
      <Typography.Text type="secondary">{mode} theme · fixture data, dev builds only</Typography.Text>

      <Section title="PageHeader">
        <PageHeader
          title="Page title"
          description="Short description of the page."
          extra={<Button type="primary">Primary action</Button>}
        />
      </Section>

      <Section title="StatusBadge">
        <Space wrap size={16}>
          <StatusBadge tone="neutral">Neutral</StatusBadge>
          <StatusBadge tone="success">Approved</StatusBadge>
          <StatusBadge tone="warning">Pending</StatusBadge>
          <StatusBadge tone="error">Revoked</StatusBadge>
          <StatusBadge tone="info">Info</StatusBadge>
          <StatusBadge tone="processing">Connecting</StatusBadge>
        </Space>
      </Section>

      <Section title="Countdown">
        <Space size={24}>
          <Countdown deadline={deadline} offsetMs={0} />
          <Countdown deadline={urgentDeadline} offsetMs={0} />
          <Countdown deadline="2000-01-01T00:00:00Z" offsetMs={0} />
        </Space>
      </Section>

      <Section title="Fingerprint">
        <Fingerprint
          value="SHA256:FIXTUREfixtureFIXTUREfixtureFIXTUREfixture0"
          label="Host key fingerprint"
        />
      </Section>

      <Section title="CopyField">
        <CopyField label="Callback URL" value="https://hallpass.example.invalid/auth/oidc/callback" />
      </Section>

      <Section title="KeyValueGrid">
        <KeyValueGrid
          items={[
            { key: 'a', label: 'Agent', value: 'fixture-agent-a' },
            { key: 'b', label: 'Server', value: 'fixture-server' },
            { key: 'c', label: 'Role', value: 'deploy' },
            { key: 'd', label: 'Expires', value: <Countdown deadline={deadline} offsetMs={0} /> },
          ]}
        />
      </Section>

      <Section title="UntrustedText">
        <Space orientation="vertical">
          <UntrustedText text={'Restart nginx on web-1 <b>not bold</b> <img src=x onerror=alert(1)>'} />
          <UntrustedText
            block
            text={'Reason with a bidi override:\u202E txt.exe\u202C and zero width:\u200B.'}
          />
        </Space>
      </Section>

      <Section title="ConfirmAction">
        <Space wrap>
          <ConfirmAction
            label="Revoke grant"
            title="Revoke this grant?"
            description="Open channels are closed immediately."
            onConfirm={() => new Promise((resolve) => setTimeout(resolve, 600))}
          />
          <ConfirmAction
            label="Enter lockdown"
            title="Enter lockdown"
            description="All agent access stops until lockdown is lifted."
            typedConfirmation="LOCKDOWN"
            onConfirm={() =>
              Promise.reject(
                new ApiError({
                  status: 409,
                  code: 'conflict',
                  detail: 'Fixture failure: shown to demonstrate error handling.',
                }),
              )
            }
          />
        </Space>
      </Section>

      <Section title="ReauthGate">
        <ReauthGate client={reauthClient} />
        <Space>
          <Button
            onClick={() => {
              reauthClient.post('/fixture').then(
                () => {
                  setReauthResult('retried after reauth: ok');
                },
                (e: unknown) => {
                  setReauthResult(e instanceof ApiError ? e.code : 'error');
                },
              );
            }}
          >
            Trigger reauth_required
          </Button>
          <Typography.Text type="secondary">Result: {reauthResult}</Typography.Text>
        </Space>
      </Section>

      <Section title="PermissionGate">
        <Space orientation="vertical" style={{ width: '100%' }}>
          <PermissionGate permission="grants.revoke" permissions={['grants.revoke']}>
            <Button danger>Allowed action</Button>
          </PermissionGate>
          <PermissionGate permission="grants.revoke" permissions={[]}>
            <Button danger>Hidden action</Button>
          </PermissionGate>
        </Space>
      </Section>

      <Section title="ConnectionBanner">
        <Space orientation="vertical" style={{ width: '100%' }}>
          <ConnectionBanner
            state={{ status: 'reconnecting', attempt: 1, lastEventAt: null, disconnectedAt: 0 }}
          />
          <ConnectionBanner
            state={{ status: 'stale', attempt: 3, lastEventAt: null, disconnectedAt: 0 }}
            onReconnect={() => undefined}
          />
          <ConnectionBanner
            state={{ status: 'disconnected', attempt: 20, lastEventAt: null, disconnectedAt: 0 }}
            onReconnect={() => undefined}
          />
        </Space>
      </Section>

      <Section title="DataTable">
        <Space orientation="vertical" style={{ width: '100%' }}>
          <DataTable<FixtureRow>
            caption="Fixture table"
            columns={FIXTURE_COLUMNS}
            rows={FIXTURE_ROWS}
            rowKey="id"
            sort={sort}
            onSortChange={setSort}
            pagination={{
              pageSize: 50,
              hasPreviousPage: false,
              hasNextPage: true,
              onPreviousPage: () => undefined,
              onNextPage: () => undefined,
              onPageSizeChange: () => undefined,
            }}
          />
          <DataTable<FixtureRow>
            caption="Fixture loading"
            columns={FIXTURE_COLUMNS}
            rows={undefined}
            rowKey="id"
            loading
          />
          <DataTable<FixtureRow>
            caption="Fixture empty"
            columns={FIXTURE_COLUMNS}
            rows={[]}
            rowKey="id"
            emptyTitle="No agents"
          />
          <DataTable<FixtureRow>
            caption="Fixture stale"
            columns={FIXTURE_COLUMNS}
            rows={FIXTURE_ROWS}
            rowKey="id"
            stale
          />
          <DataTable<FixtureRow>
            caption="Fixture error"
            columns={FIXTURE_COLUMNS}
            rows={undefined}
            rowKey="id"
            error={new ApiError({ status: 500, code: 'internal', detail: 'Fixture server error.' })}
            onRetry={() => undefined}
          />
        </Space>
      </Section>

      <Section title="ChartCard">
        <ChartCard
          title="Fixture series"
          summary="Gallery fixture: two series over four buckets, used only to render the chart component."
          option={{
            tooltip: { trigger: 'axis' },
            legend: { top: 0 },
            grid: { left: 40, right: 16, top: 32, bottom: 24 },
            xAxis: { type: 'category', data: ['t1', 't2', 't3', 't4'] },
            yAxis: { type: 'value' },
            series: [
              { name: 'Series A', type: 'line', data: [1, 3, 2, 4] },
              { name: 'Series B', type: 'line', data: [2, 1, 3, 2] },
            ],
          }}
          table={{
            columns: [
              { key: 'bucket', title: 'Bucket' },
              { key: 'a', title: 'Series A' },
              { key: 'b', title: 'Series B' },
            ],
            rows: [
              { bucket: 't1', a: 1, b: 2 },
              { bucket: 't2', a: 3, b: 1 },
              { bucket: 't3', a: 2, b: 3 },
              { bucket: 't4', a: 4, b: 2 },
            ],
          }}
        />
        <div style={{ height: 12 }} />
        <ChartCard
          title="Fixture empty"
          summary="No data."
          option={{}}
          table={{ columns: [], rows: [] }}
          empty
        />
      </Section>

      <Section title="TerminalReplay (stub)">
        <TerminalReplay chunks={HOSTILE_OUTPUT} ariaLabel="Fixture terminal output" rows={6} cols={80} />
      </Section>

      <Section title="States">
        <Space orientation="vertical" style={{ width: '100%' }}>
          <Card size="small">
            <LoadingState />
          </Card>
          <Card size="small">
            <EmptyState title="No requests" description="Requests from agents appear here." />
          </Card>
          <Card size="small">
            <ErrorState
              error={
                new ApiError({ status: 0, code: 'network_error', detail: 'The server could not be reached.' })
              }
              onRetry={() => undefined}
            />
          </Card>
          <Card size="small">
            <PermissionDenied />
          </Card>
          <Card size="small">
            <NotImplemented feature="Example page" workPackage="WP20" />
          </Card>
        </Space>
      </Section>
    </div>
  );
}

export default function DsGallery() {
  return (
    <main className="hp-gallery" aria-label="Design system gallery">
      <h1 className="hp-visually-hidden">Design system gallery</h1>
      <ThemeProvider mode="light">
        <GalleryPane mode="light" />
      </ThemeProvider>
      <ThemeProvider mode="dark">
        <GalleryPane mode="dark" />
      </ThemeProvider>
    </main>
  );
}
