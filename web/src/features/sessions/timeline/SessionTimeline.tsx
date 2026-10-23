import { useInfiniteQuery } from '@tanstack/react-query';
import { Button } from 'antd';

import { api } from '../../../api/client';
import { qk } from '../../../api/queryKeys';
import type { TimelineEvent } from '../../../api/types';
import { EmptyState, ErrorState, LoadingState } from '../../../ds/states';
import { StatusBadge } from '../../../ds/StatusBadge';
import { formatDateTime, shortId } from '../../../lib/format';
import { ProvenanceBadge } from '../ProvenanceBadge';
import { HIDDEN_FIELDS, timelineFields, timelineLabel, timelineProvenance } from './labels';

const PAGE = 100;

/**
 * Unified timeline of one access session across its connections and channels (HP-REC-010, HP-UI-004),
 * ordered by the server-assigned sequence and paged with `after_seq`.
 */
export function SessionTimeline({ sessionId }: { sessionId: string }) {
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

  if (q.isPending) {
    return <LoadingState label="Loading timeline…" />;
  }
  if (q.isError) {
    return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
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
  if (events.length === 0) {
    return <EmptyState title="No timeline events yet" />;
  }
  return (
    <>
      <ol className="hp-session-timeline" aria-label="Session timeline">
        {events.map((ev) => {
          const { label, tone } = timelineLabel(ev.type);
          const fields = timelineFields(ev.data).filter((f) => !HIDDEN_FIELDS.has(f.key));
          const provenance = timelineProvenance(ev.type);
          return (
            <li key={ev.id} className="hp-session-timeline__item">
              <div className="hp-session-timeline__head">
                <time dateTime={ev.at} className="hp-session-timeline__time">
                  {formatDateTime(ev.at)}
                </time>
                <StatusBadge tone={tone}>{label}</StatusBadge>
                {provenance ? <ProvenanceBadge provenance={provenance} /> : null}
                {ev.seq !== null && ev.seq !== undefined ? (
                  <span className="hp-session-timeline__meta">#{ev.seq}</span>
                ) : null}
                {ev.channel_id ? (
                  <span className="hp-session-timeline__meta" title={ev.channel_id}>
                    channel <code className="hp-mono">{shortId(ev.channel_id)}</code>
                  </span>
                ) : ev.connection_id ? (
                  <span className="hp-session-timeline__meta" title={ev.connection_id}>
                    connection <code className="hp-mono">{shortId(ev.connection_id)}</code>
                  </span>
                ) : null}
              </div>
              {fields.length > 0 ? (
                <dl className="hp-session-timeline__data">
                  {fields.map((f) => (
                    <div key={f.key}>
                      <dt>{f.key}</dt>
                      <dd className="hp-mono">{f.value}</dd>
                    </div>
                  ))}
                </dl>
              ) : null}
            </li>
          );
        })}
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
