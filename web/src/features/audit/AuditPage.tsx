import { SafetyCertificateOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Card, Form, Input, Modal, Space, type TableColumnsType } from 'antd';
import { useEffect, useState } from 'react';

import { api } from '../../api/client';
import { auditListQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { AuditEvent } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { SavedFilters } from '../../ds/SavedFilters';
import { ErrorState, PermissionDenied } from '../../ds/states';
import { StatusBadge, type StatusTone } from '../../ds/StatusBadge';
import { revealControls } from '../../ds/untrusted';
import { formatDateTime, shortId } from '../../lib/format';
import { useCursorPager } from '../../lib/useCursorPager';
import { usePermissions } from '../../lib/usePermissions';
import { OperatorName } from '../../shared/names';
import { useSseState } from '../../stores/sse';
import { auditSearchToValues, formatDetails, parseAuditSearch, type AuditSearch } from './auditFilters';

const OUTCOME: Record<string, [StatusTone, string]> = {
  success: ['success', 'Success'],
  failure: ['error', 'Failure'],
  denied: ['warning', 'Denied'],
};

function OutcomeBadge({ outcome }: { outcome: string }) {
  const [tone, label] = OUTCOME[outcome] ?? ['neutral', outcome];
  return <StatusBadge tone={tone}>{label}</StatusBadge>;
}

/** Chain verification (HP-AUD-*, `GET /audit-events/verify`): only runs when the operator asks. */
function VerifyChain() {
  const verify = useQuery({
    queryKey: qk.auditVerify,
    queryFn: ({ signal }) => api.call('get', '/api/v1/audit-events/verify', { signal }),
    enabled: false,
    retry: false,
    gcTime: 0,
  });
  return (
    <Space orientation="vertical" style={{ width: '100%' }}>
      <Button
        icon={<SafetyCertificateOutlined />}
        loading={verify.isFetching}
        onClick={() => void verify.refetch()}
      >
        Verify hash chain
      </Button>
      <div aria-live="polite">
        {verify.isError ? (
          <ErrorState error={verify.error} title="Verification could not run" />
        ) : verify.data ? (
          verify.data.ok ? (
            <Alert
              type="success"
              showIcon
              title={`Hash chain intact: ${String(verify.data.events)} events verified.`}
              description="Every event links to its predecessor. This proves internal consistency, not that nothing was removed from the end; compare with external anchors for that."
            />
          ) : (
            <Alert
              type="error"
              showIcon
              title="Hash chain verification FAILED"
              description={
                <>
                  {String(verify.data.events)} events checked.{' '}
                  {verify.data.problem ? (
                    <span className="hp-mono">{revealControls(verify.data.problem)}</span>
                  ) : null}
                </>
              }
            />
          )
        ) : null}
      </div>
    </Space>
  );
}

function FilterForm({ search, onChange }: { search: AuditSearch; onChange: (s: AuditSearch) => void }) {
  const [form] = Form.useForm<AuditSearch>();
  useEffect(() => {
    form.setFieldsValue({
      action: search.action ?? '',
      actor_id: search.actor_id ?? '',
      target_id: search.target_id ?? '',
    });
  }, [form, search]);
  return (
    <Form<AuditSearch>
      form={form}
      layout="inline"
      aria-label="Audit filters"
      onFinish={(v) => {
        onChange(parseAuditSearch(v as Record<string, unknown>));
      }}
      style={{ rowGap: 8 }}
    >
      <Form.Item label="Action" name="action">
        <Input placeholder="e.g. request.approved" allowClear spellCheck={false} />
      </Form.Item>
      <Form.Item label="Actor ID" name="actor_id">
        <Input allowClear spellCheck={false} />
      </Form.Item>
      <Form.Item label="Target ID" name="target_id">
        <Input allowClear spellCheck={false} />
      </Form.Item>
      <Form.Item>
        <Space>
          <Button type="primary" htmlType="submit">
            Apply
          </Button>
          <Button
            onClick={() => {
              onChange({});
            }}
          >
            Clear
          </Button>
        </Space>
      </Form.Item>
    </Form>
  );
}

export interface AuditPageProps {
  search: AuditSearch;
  onSearchChange: (search: AuditSearch) => void;
}

/** Audit log (HP-AUD-*): server-filtered, cursor-paginated, with saved filters and chain verification. */
export function AuditPage({ search, onSearchChange }: AuditPageProps) {
  const { can, loading } = usePermissions();
  const [pageSize, setPageSize] = useState(50);
  const pager = useCursorPager(JSON.stringify([search, pageSize]));
  const sse = useSseState();
  const [details, setDetails] = useState<AuditEvent | null>(null);
  const list = useQuery({
    ...auditListQueryOptions({
      ...search,
      limit: pageSize,
      ...(pager.cursor ? { cursor: pager.cursor } : {}),
    }),
    enabled: can('audit.read'),
    placeholderData: (prev) => prev,
  });

  if (loading) {
    return null;
  }
  if (!can('audit.read')) {
    return (
      <>
        <PageHeader title="Audit log" />
        <PermissionDenied />
      </>
    );
  }

  const cols: TableColumnsType<AuditEvent> = [
    { key: 'seq', title: 'Seq', render: (_v, e) => <span className="hp-mono">{String(e.seq)}</span> },
    { key: 'at', title: 'Time', render: (_v, e) => formatDateTime(e.at) },
    {
      key: 'actor',
      title: 'Actor',
      render: (_v, e) =>
        e.actor_type === 'operator' && e.actor_id ? (
          <OperatorName id={e.actor_id} />
        ) : (
          <span>
            {e.actor_type}
            {e.actor_id ? (
              <>
                {' '}
                <code className="hp-mono" title={e.actor_id}>
                  {shortId(e.actor_id)}
                </code>
              </>
            ) : null}
          </span>
        ),
    },
    { key: 'action', title: 'Action', render: (_v, e) => <code className="hp-mono">{e.action}</code> },
    {
      key: 'target',
      title: 'Target',
      render: (_v, e) =>
        e.target_type || e.target_id ? (
          <span>
            {e.target_type ?? ''}{' '}
            {e.target_id ? (
              <code className="hp-mono" title={e.target_id}>
                {shortId(e.target_id)}
              </code>
            ) : null}
          </span>
        ) : (
          '—'
        ),
    },
    { key: 'outcome', title: 'Outcome', render: (_v, e) => <OutcomeBadge outcome={e.outcome} /> },
    {
      key: 'ip',
      title: 'Source IP',
      render: (_v, e) => (e.source_ip ? <span className="hp-mono">{e.source_ip}</span> : '—'),
    },
    {
      key: 'corr',
      title: 'Correlation',
      render: (_v, e) =>
        e.correlation_id ? (
          <code className="hp-mono" title={e.correlation_id}>
            {shortId(e.correlation_id, 8)}
          </code>
        ) : (
          '—'
        ),
    },
    {
      key: 'details',
      title: <span className="hp-visually-hidden">Details</span>,
      fixed: 'right',
      render: (_v, e) => (
        <Button
          size="small"
          type="link"
          aria-label={`Details of event ${String(e.seq)}`}
          onClick={() => {
            setDetails(e);
          }}
        >
          Details
        </Button>
      ),
    },
  ];

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Append-only, hash-chained record of security-relevant actions."
        extra={can('audit.verify') ? <VerifyChain /> : null}
      />
      <Card size="small">
        <Space orientation="vertical" size={12} style={{ width: '100%' }}>
          <Space wrap align="start" style={{ justifyContent: 'space-between', width: '100%' }}>
            <FilterForm search={search} onChange={onSearchChange} />
            <SavedFilters
              table="audit"
              current={auditSearchToValues(search)}
              onApply={(f) => {
                onSearchChange(parseAuditSearch(f));
              }}
            />
          </Space>
          <DataTable<AuditEvent>
            caption="Audit events"
            columns={cols}
            rows={list.data?.items}
            rowKey="id"
            loading={list.isPending}
            fetching={list.isFetching}
            error={list.error}
            onRetry={() => void list.refetch()}
            stale={sse.status === 'stale' || sse.status === 'disconnected'}
            emptyTitle="No audit events"
            emptyDescription={Object.keys(search).length ? 'No events match these filters.' : undefined}
            pagination={{
              pageSize,
              hasPreviousPage: pager.hasPrevious,
              hasNextPage: Boolean(list.data?.next_cursor),
              onPreviousPage: pager.previous,
              onNextPage: () => {
                pager.next(list.data?.next_cursor);
              },
              onPageSizeChange: setPageSize,
            }}
          />
        </Space>
      </Card>
      <Modal
        open={details !== null}
        title={details ? `Event ${String(details.seq)} · ${details.action}` : ''}
        footer={null}
        width={720}
        onCancel={() => {
          setDetails(null);
        }}
      >
        {details ? (
          <>
            <p>
              Details may include agent- or destination-provided values. They are shown as text, with hidden
              characters revealed.
            </p>
            <pre
              className="hp-mono"
              style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 420, overflow: 'auto' }}
            >
              {revealControls(formatDetails(details.details))}
            </pre>
          </>
        ) : null}
      </Modal>
    </>
  );
}
