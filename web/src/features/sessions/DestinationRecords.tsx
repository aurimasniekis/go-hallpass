import { useQuery } from '@tanstack/react-query';
import { Button, Space } from 'antd';
import type { TableColumnsType } from 'antd';
import { useState } from 'react';

import { destinationRecordQueryOptions, sessionDestinationRecordsQueryOptions } from '../../api/queries';
import type { DestinationRecord } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { ErrorState, LoadingState } from '../../ds/states';
import { UntrustedText } from '../../ds/UntrustedText';
import { formatDateTime } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { ProvenanceBadge } from './ProvenanceBadge';

/**
 * Full record (exe, argv, cwd), fetched only when the operator expands a row: every read is audited
 * server-side. All fields are destination-provided text, shown strictly as plain text.
 */
export function RecordDetails({ id }: { id: string }) {
  const q = useQuery(destinationRecordQueryOptions(id));
  if (q.isPending) {
    return <LoadingState label="Loading reported command…" />;
  }
  if (q.isError) {
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  }
  const r = q.data;
  if (r.purged) {
    return <p>The command details were purged by retention; only metadata remains.</p>;
  }
  return (
    <KeyValueGrid
      columns={1}
      items={[
        { key: 'exe', label: 'Executable', value: <UntrustedText text={r.exe} source="the destination" /> },
        {
          key: 'argv',
          label: 'Arguments',
          value:
            r.argv && r.argv.length > 0 ? (
              <ol style={{ margin: 0, paddingLeft: 18 }}>
                {r.argv.map((arg, i) => (
                  <li key={i}>
                    <UntrustedText text={arg} source="the destination" />
                  </li>
                ))}
              </ol>
            ) : (
              '—'
            ),
        },
        {
          key: 'cwd',
          label: 'Working directory',
          value: <UntrustedText text={r.cwd} source="the destination" />,
        },
        { key: 'trunc', label: 'Truncated by collector', value: r.truncated ? 'Yes' : 'No' },
      ]}
    />
  );
}

/**
 * Destination-reported commands (WP25). These come from a collector on the destination host: they are
 * labelled "destination-reported, unverified" everywhere and never treated as proof (HP-REC-006).
 */
export function DestinationRecords({ sessionId }: { sessionId: string }) {
  const { can } = usePermissions();
  const q = useQuery(sessionDestinationRecordsQueryOptions(sessionId));
  const [open, setOpen] = useState<string | null>(null);
  const columns: TableColumnsType<DestinationRecord> = [
    { key: 'reported', title: 'Reported', render: (_, r) => formatDateTime(r.reported_at) },
    { key: 'received', title: 'Received', render: (_, r) => formatDateTime(r.received_at) },
    { key: 'prov', title: 'Provenance', render: () => <ProvenanceBadge provenance="destination-audit" /> },
    { key: 'corr', title: 'Correlation', render: (_, r) => r.correlation },
    { key: 'conf', title: 'Confidence', render: (_, r) => r.confidence },
    { key: 'after', title: 'After session end', render: (_, r) => (r.after_session_end ? 'Yes' : 'No') },
    { key: 'purged', title: 'Purged', render: (_, r) => (r.purged ? 'Yes' : 'No') },
    {
      key: 'details',
      title: 'Details',
      render: (_, r) =>
        can('recording.play') ? (
          <Button
            size="small"
            aria-expanded={open === r.id}
            aria-label={`${open === r.id ? 'Hide' : 'Show'} reported command reported ${formatDateTime(r.reported_at)}`}
            onClick={() => {
              setOpen(open === r.id ? null : r.id);
            }}
          >
            {open === r.id ? 'Hide' : 'Show command'}
          </Button>
        ) : (
          'Needs recording.play'
        ),
    },
  ];
  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <p className="hp-session-timeline__meta" style={{ margin: 0 }}>
        Reported by a collector on the destination host. HallPass cannot verify these reports. Opening a
        command is recorded in the audit log.
      </p>
      <DataTable<DestinationRecord>
        caption="Destination-reported commands"
        columns={columns}
        rows={q.data?.items}
        rowKey="id"
        loading={q.isPending}
        error={q.error}
        onRetry={() => void q.refetch()}
        emptyTitle="No destination reports"
        emptyDescription="Shown when a destination-side collector is configured for this server."
      />
      {open ? (
        <section aria-label="Reported command details">
          <RecordDetails id={open} />
        </section>
      ) : null}
    </Space>
  );
}
