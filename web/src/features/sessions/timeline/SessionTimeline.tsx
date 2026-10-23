import {
  CheckCircleOutlined,
  ClockCircleOutlined,
  CloseCircleOutlined,
  CloudServerOutlined,
  CodeOutlined,
  DesktopOutlined,
  FileTextOutlined,
  InfoCircleOutlined,
  LoginOutlined,
  LogoutOutlined,
  MinusCircleOutlined,
  PoweroffOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
  VideoCameraOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { Button } from 'antd';
import { useMemo, useState, type ReactNode } from 'react';

import { api } from '../../../api/client';
import {
  operatorsQueryOptions,
  policyRulesQueryOptions,
  sessionChannelsQueryOptions,
} from '../../../api/queries';
import { qk } from '../../../api/queryKeys';
import type { TimelineEvent } from '../../../api/types';
import { EmptyState, ErrorState, LoadingState } from '../../../ds/states';
import { formatDate, formatDateTime, formatTime } from '../../../lib/format';
import { usePermissions } from '../../../lib/usePermissions';
import { RecordDetails } from '../DestinationRecords';
import { ProvenanceBadge } from '../ProvenanceBadge';
import { describeTimeline, type ChannelInfo, type TimelineEntry } from './describe';

const PAGE = 100;

function iconFor(entry: TimelineEntry): ReactNode {
  switch (entry.type) {
    case 'request.created':
      return <FileTextOutlined />;
    case 'request.approved':
      return <CheckCircleOutlined />;
    case 'request.denied':
      return <CloseCircleOutlined />;
    case 'request.expired':
    case 'request.canceled':
    case 'grant.revoked':
      return <StopOutlined />;
    case 'grant.activated':
      return <SafetyCertificateOutlined />;
    case 'grant.expired':
    case 'grant.clamped':
      return <ClockCircleOutlined />;
    case 'connection.opened':
      return <LoginOutlined />;
    case 'connection.closed':
      return <LogoutOutlined />;
    case 'exec.requested':
      return <CodeOutlined />;
    case 'channel.opened':
      return <DesktopOutlined />;
    case 'channel.exited':
      return <MinusCircleOutlined />;
    case 'channel.failed':
      return <WarningOutlined />;
    case 'recording.failed':
      return <VideoCameraOutlined />;
    case 'access_session.closed':
      return <PoweroffOutlined />;
    case 'destination.exec':
      return <CloudServerOutlined />;
    default:
      return <InfoCircleOutlined />;
  }
}

function TimelineRow({ entry, canPlay }: { entry: TimelineEntry; canPlay: boolean }) {
  const [showCommand, setShowCommand] = useState(false);
  return (
    <li
      className={`hp-tl__row hp-tl__row--depth-${String(entry.depth)} hp-tl__row--${entry.tone}`}
      data-category={entry.category}
    >
      <time dateTime={entry.at} className="hp-tl__time" title={formatDateTime(entry.at)}>
        {formatTime(entry.at)}
      </time>
      <span className="hp-tl__group" title={entry.channelId ?? entry.connectionId ?? undefined}>
        {entry.group ?? ''}
      </span>
      <div className="hp-tl__main">
        <span className="hp-tl__icon" aria-hidden="true">
          {iconFor(entry)}
        </span>
        <div className="hp-tl__body">
          <span className="hp-tl__text">{entry.text}</span>
          {entry.provenance ? (
            <span className="hp-tl__badge">
              <ProvenanceBadge provenance={entry.provenance} />
            </span>
          ) : null}
          <details className="hp-tl__details">
            <summary>Details</summary>
            <dl className="hp-tl__data">
              {entry.details.map((f) => (
                <div key={f.key}>
                  <dt>{f.key}</dt>
                  <dd className="hp-mono">{f.value}</dd>
                </div>
              ))}
            </dl>
            {entry.recordId && canPlay ? (
              <div style={{ marginTop: 8 }}>
                {showCommand ? (
                  <RecordDetails id={entry.recordId} />
                ) : (
                  <Button
                    size="small"
                    onClick={() => {
                      setShowCommand(true);
                    }}
                  >
                    Show reported command (audited)
                  </Button>
                )}
              </div>
            ) : null}
          </details>
        </div>
      </div>
    </li>
  );
}

/**
 * Unified timeline of one access session across its connections and channels (HP-REC-010, HP-UI-004),
 * ordered by the server-assigned sequence and paged with `after_seq`. One sentence per event; channel
 * events are indented under their connection; raw fields sit in a collapsed "Details" section.
 */
export function SessionTimeline({ sessionId }: { sessionId: string }) {
  const { can, me } = usePermissions();
  const channels = useQuery(sessionChannelsQueryOptions(sessionId));
  const operators = useQuery({ ...operatorsQueryOptions(), enabled: can('operators.manage') });
  const rules = useQuery({ ...policyRulesQueryOptions(), enabled: can('policy.read') });
  const q = useInfiniteQuery({
    queryKey: qk.sessionTimeline(sessionId),
    initialPageParam: 0,
    queryFn: ({ pageParam, signal }) =>
      api.call('get', '/api/v1/access-sessions/{id}/timeline', {
        path: { id: sessionId },
        query: { after_seq: pageParam, limit: PAGE },
        signal,
      }),
    getNextPageParam: (last) => last.next_after_seq ?? undefined,
  });

  const channelsData = channels.data;
  const operatorsData = operators.data;
  const rulesData = rules.data;
  const entries = useMemo(() => {
    if (!q.data) {
      return [];
    }
    const seen = new Set<string>();
    const events: TimelineEvent[] = [];
    for (const page of q.data.pages) {
      for (const ev of page.items) {
        if (!seen.has(ev.id)) {
          seen.add(ev.id);
          events.push(ev);
        }
      }
    }
    events.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0) || a.at.localeCompare(b.at));
    const chanMap = new Map<string, ChannelInfo>(
      (channelsData?.items ?? []).map((c) => [
        c.id,
        { kind: c.kind, pty: c.pty, connection_id: c.connection_id },
      ]),
    );
    return describeTimeline(events, {
      channels: chanMap,
      operatorName: (id) =>
        me?.operator.id === id
          ? me.operator.display_name
          : operatorsData?.items.find((o) => o.id === id)?.display_name,
      ruleName: (id) => rulesData?.items.find((r) => r.id === id)?.name,
    });
  }, [q.data, channelsData, operatorsData, rulesData, me]);

  if (q.isPending) {
    return <LoadingState label="Loading timeline…" />;
  }
  if (q.isError) {
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  }
  if (entries.length === 0) {
    return <EmptyState title="No timeline events yet" />;
  }
  const canPlay = can('recording.play');
  const rows: ReactNode[] = [];
  let day = '';
  for (const e of entries) {
    const d = formatDate(e.at);
    if (d !== day) {
      day = d;
      rows.push(
        <li key={`day-${d}`} className="hp-tl__day">
          {d}
        </li>,
      );
    }
    rows.push(<TimelineRow key={e.id} entry={e} canPlay={canPlay} />);
  }
  return (
    <>
      <p className="hp-legend" style={{ marginTop: 0 }}>
        <strong>C1</strong> marks the agent&apos;s first SSH connection in this session and{' '}
        <strong>C1·2</strong> its second channel; channel events are indented under their connection.
      </p>
      <ol className="hp-tl" aria-label="Session timeline">
        {rows}
      </ol>
      {q.hasNextPage ? (
        <Button
          onClick={() => void q.fetchNextPage()}
          loading={q.isFetchingNextPage}
          style={{ marginTop: 8 }}
        >
          Load more events
        </Button>
      ) : null}
    </>
  );
}
