import { useQuery } from '@tanstack/react-query';
import { Card, Col, Row } from 'antd';

import { meQueryOptions } from '../../api/queries';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, NotImplemented } from '../../ds/states';
import { StatusBadge, type StatusTone } from '../../ds/StatusBadge';
import { useSseState, type SseStatus } from '../../stores/sse';

const SSE_LABEL: Record<SseStatus, [StatusTone, string]> = {
  idle: ['neutral', 'Not started'],
  connecting: ['processing', 'Connecting'],
  connected: ['success', 'Connected'],
  reconnecting: ['warning', 'Reconnecting'],
  stale: ['warning', 'Stale'],
  disconnected: ['error', 'Disconnected'],
};

/**
 * WP19 dashboard placeholder. Shows only real data (the signed-in operator and live-update status).
 * Metric charts (docs/PLAN.md §14.6) arrive in WP20 and will read the /stats/* endpoints; until then
 * no numbers are displayed.
 */
export function DashboardPage() {
  const me = useQuery(meQueryOptions());
  const sse = useSseState();
  const [tone, label] = SSE_LABEL[sse.status];

  return (
    <>
      <PageHeader title="Dashboard" description="Overview of access activity." />
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="Signed in as" size="small">
            {me.isPending ? (
              <LoadingState />
            ) : me.isError ? (
              <ErrorState
                error={me.error}
                onRetry={() => {
                  void me.refetch();
                }}
              />
            ) : (
              <KeyValueGrid
                items={[
                  { key: 'name', label: 'Operator', value: me.data.display_name },
                  {
                    key: 'roles',
                    label: 'Roles',
                    value: me.data.roles.length ? me.data.roles.join(', ') : '—',
                  },
                ]}
              />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="Live updates" size="small">
            <KeyValueGrid
              items={[
                { key: 'status', label: 'Stream', value: <StatusBadge tone={tone}>{label}</StatusBadge> },
                {
                  key: 'last',
                  label: 'Last event',
                  value:
                    sse.lastEventAt === null
                      ? 'None received yet'
                      : new Date(sse.lastEventAt).toLocaleTimeString(),
                },
              ]}
            />
          </Card>
        </Col>
        <Col span={24}>
          <Card title="Metrics" size="small">
            <NotImplemented feature="Dashboard metrics" workPackage="WP20 (backed by /api/v1/stats/*)" />
          </Card>
        </Col>
      </Row>
    </>
  );
}
