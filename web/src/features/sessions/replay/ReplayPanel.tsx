import { CaretRightOutlined, PauseOutlined } from '@ant-design/icons';
import { useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Select, Slider, Space, Switch } from 'antd';
import { useEffect, useMemo, useRef, useState } from 'react';

import { api } from '../../../api/client';
import { errorMessage } from '../../../api/errors';
import { qk } from '../../../api/queryKeys';
import type { Channel, Segment } from '../../../api/types';
import { TerminalReplay, type TerminalHandle } from '../../../ds/TerminalReplay';
import { UntrustedText } from '../../../ds/UntrustedText';
import { formatDateTime, shortId } from '../../../lib/format';
import { channelKind } from '../../../shared/channelClose';
import { loadSegmentRecords, type FetchRecordPage, type SegmentLoad } from './pager';
import { formatClock, ReplayPlayer, SPEEDS, type PlayerSnapshot } from './player';
import { ProvenanceBadge } from '../ProvenanceBadge';
import { buildTrack, type Frame, type Track } from './track';

/** Segments the records API refuses (`not_found`); listed but not requested. */
const UNAVAILABLE = new Set(['deleted', 'missing', 'failed']);

function channelLabel(ch: Channel, index: number): string {
  return `${String(index + 1)}. ${channelKind(ch)} · ${formatDateTime(ch.opened_at)} · ${shortId(ch.id)}`;
}

interface Loaded {
  channelId: string;
  kind: 'pty' | 'exec';
  /** The channel had a PTY: output is replayed raw. Without one, bare LF is translated to CRLF. */
  pty: boolean;
  parts: { segment: Segment; load: SegmentLoad }[];
  skipped: Segment[];
}

/**
 * Per-channel replay (HP-REC-010: concurrent terminals are separate tracks). Records are requested only
 * when the operator asks (each page access is audited, HP-REC-014) and written into hardened read-only
 * terminals (HP-UI-013). Exec stdout and stderr play in separate panes.
 */
export function ReplayPanel({
  channels,
  segments,
}: {
  channels: readonly Channel[];
  segments: readonly Segment[];
}) {
  const queryClient = useQueryClient();
  const playable = useMemo(
    () => channels.filter((ch) => segments.some((s) => s.channel_id === ch.id)),
    [channels, segments],
  );
  const [selected, setChannelId] = useState<string | undefined>(undefined);
  const channelId = selected ?? playable[0]?.id;
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [shortenIdle, setShortenIdle] = useState(true);
  const abort = useRef<AbortController | null>(null);

  useEffect(() => () => abort.current?.abort(), []);

  const channel = channels.find((c) => c.id === channelId);
  const channelSegments = segments
    .filter((s) => s.channel_id === channelId)
    .sort((a, b) => a.ordinal - b.ordinal);

  const load = async () => {
    if (!channel) {
      return;
    }
    abort.current?.abort();
    const ctrl = new AbortController();
    abort.current = ctrl;
    setLoading(true);
    setError(null);
    setLoaded(null);
    const fetchPage: FetchRecordPage = (segmentId, fromSeq, signal) => {
      const seg = channelSegments.find((s) => s.id === segmentId);
      return queryClient.query({
        queryKey: qk.recordingPage(segmentId, fromSeq),
        queryFn: () =>
          api.call('get', '/api/v1/recordings/{id}/records', {
            path: { id: segmentId },
            query: { from_seq: fromSeq },
            signal,
          }),
        // Finalized pages never change; pages of a segment still recording may grow.
        staleTime: seg?.state === 'finalized' ? Infinity : 0,
      });
    };
    try {
      const parts: Loaded['parts'] = [];
      const skipped: Segment[] = [];
      for (const seg of channelSegments) {
        if (UNAVAILABLE.has(seg.state)) {
          skipped.push(seg);
          continue;
        }
        parts.push({ segment: seg, load: await loadSegmentRecords(seg.id, fetchPage, ctrl.signal) });
      }
      if (!ctrl.signal.aborted) {
        setLoaded({
          channelId: channel.id,
          kind: channel.pty || channel.kind === 'shell' ? 'pty' : 'exec',
          pty: channel.pty,
          parts,
          skipped,
        });
      }
    } catch (e) {
      if (!(e instanceof DOMException && e.name === 'AbortError')) {
        setError(e);
      }
    } finally {
      if (abort.current === ctrl) {
        setLoading(false);
      }
    }
  };

  if (channels.length === 0) {
    return <Alert type="info" showIcon title="This session has no channels to replay." />;
  }
  if (playable.length === 0) {
    return <Alert type="info" showIcon title="No recording segments exist for this session." />;
  }

  const track =
    loaded && loaded.channelId === channelId
      ? buildTrack(loaded.kind, loaded.parts, { idleCapMs: shortenIdle ? 2000 : 0 })
      : null;

  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <div className="hp-replay-picker">
        <Select<string>
          aria-label="Channel to replay"
          value={channelId}
          className="hp-replay-picker__select"
          onChange={(v) => {
            abort.current?.abort();
            setLoaded(null);
            setLoading(false);
            setChannelId(v);
          }}
          options={channels.map((ch, i) => ({
            value: ch.id,
            label: channelLabel(ch, i),
            disabled: !playable.includes(ch),
          }))}
        />
        <Button type="primary" onClick={() => void load()} loading={loading} disabled={!channel}>
          {loaded?.channelId === channelId ? 'Reload recording' : 'Load recording'}
        </Button>
        <Space>
          <Switch
            checked={shortenIdle}
            onChange={setShortenIdle}
            aria-label="Shorten idle gaps longer than 2 seconds"
          />
          <span aria-hidden="true">Shorten idle gaps &gt; 2 s</span>
        </Space>
      </div>
      <p className="hp-session-timeline__meta" style={{ margin: 0 }}>
        Loading a recording decrypts it on the server; every page read is recorded in the audit log.
      </p>
      {channelSegments.some((s) => UNAVAILABLE.has(s.state)) ? (
        <Alert
          type="warning"
          showIcon
          title="Some segments of this channel are unavailable"
          description={channelSegments
            .filter((s) => UNAVAILABLE.has(s.state))
            .map((s) => `segment ${String(s.ordinal)}: ${s.state}`)
            .join('; ')}
        />
      ) : null}
      {error !== null ? (
        <Alert type="error" showIcon title="Could not load the recording" description={errorMessage(error)} />
      ) : null}
      {track ? (
        <TrackView
          key={`${loaded?.channelId ?? ''}-${String(shortenIdle)}`}
          track={track}
          pty={loaded?.pty ?? true}
        />
      ) : null}
    </Space>
  );
}

function TrackWarnings({ track }: { track: Track }) {
  return (
    <>
      {track.incomplete ? (
        <Alert
          type="warning"
          showIcon
          title="Incomplete (interrupted)"
          description="The recording ended without a finalized footer (for example after a crash or a lost connection). What was recorded is shown."
        />
      ) : null}
      {track.truncated ? (
        <Alert
          type="warning"
          showIcon
          title="Recording truncated in the browser"
          description="Only the first part of this very large recording was loaded."
        />
      ) : null}
      {track.inputRecords > 0 ? (
        <Alert
          type="info"
          showIcon
          title={`${String(track.inputRecords)} keyboard input record(s) are not replayed`}
          description="Recorded input may contain secrets such as passwords (HP-REC-005). HallPass does not redact secrets."
        />
      ) : null}
      {track.unknownRecords + track.invalidRecords > 0 ? (
        <Alert
          type="info"
          showIcon
          title={`${String(track.unknownRecords)} unknown and ${String(track.invalidRecords)} malformed record(s) were skipped`}
        />
      ) : null}
    </>
  );
}

/** Exec stdout/stderr panes: no terminal size was negotiated. */
const EXEC_PANE = { cols: 100, rows: 16 };
/** A shell without a PTY never sent a window size; use a wider pane than the 80-column default. */
const NO_PTY_SHELL = { cols: 120, rows: 24 };

function paneSize(track: Track, pty: boolean): { cols: number; rows: number } {
  if (track.kind !== 'pty') {
    return EXEC_PANE;
  }
  return pty ? track.initialSize : NO_PTY_SHELL;
}

function TrackView({ track, pty }: { track: Track; pty: boolean }) {
  const main = useRef<TerminalHandle>(null);
  const stderr = useRef<TerminalHandle>(null);
  const [snap, setSnap] = useState<PlayerSnapshot>({
    status: 'idle',
    positionMs: 0,
    durationMs: 0,
    speed: 1,
  });
  const player = useRef<ReplayPlayer<Frame> | null>(null);
  // Position sampled while playing, tagged with the snapshot it belongs to (a seek emits a new snapshot).
  const [live, setLive] = useState<{ snap: PlayerSnapshot; pos: number } | null>(null);

  useEffect(() => {
    const p = new ReplayPlayer<Frame>(
      {
        reset: () => {
          main.current?.reset(paneSize(track, pty));
          stderr.current?.reset(EXEC_PANE);
        },
        apply: (f) => {
          switch (f.kind) {
            case 'output':
            case 'stdout':
              if (f.bytes) {
                main.current?.write(f.bytes);
              }
              break;
            case 'stderr':
              if (f.bytes) {
                stderr.current?.write(f.bytes);
              }
              break;
            case 'resize':
              if (f.cols !== undefined && f.rows !== undefined) {
                main.current?.resize(f.cols, f.rows);
              }
              break;
          }
        },
      },
      undefined,
      setSnap,
    );
    player.current = p;
    p.load(track.frames, track.durationMs);
    return () => {
      p.dispose();
      player.current = null;
    };
  }, [track, pty]);

  // While playing, sample the player position for the time display and seek bar.
  useEffect(() => {
    if (snap.status !== 'playing') {
      return;
    }
    const id = setInterval(() => {
      setLive({ snap, pos: player.current?.position() ?? snap.positionMs });
    }, 250);
    return () => {
      clearInterval(id);
    };
  }, [snap]);
  const position = live?.snap === snap ? live.pos : snap.positionMs;
  const exits = track.events.filter((e) => e.kind === 'exit');
  const notices = track.events.filter((e) => e.kind === 'notice' || e.kind === 'signal');

  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <TrackWarnings track={track} />
      {track.kind === 'exec' || track.command ? (
        <div>
          <strong>Command</strong>{' '}
          {track.command ? (
            <>
              <ProvenanceBadge provenance={track.command.provenance} />
              <div style={{ marginTop: 4 }}>
                <UntrustedText text={track.command.text} source="the agent's exec request" block />
              </div>
            </>
          ) : (
            <span>Not recorded</span>
          )}
        </div>
      ) : null}
      <div className="hp-replay-controls" role="group" aria-label="Playback controls">
        <Button
          type="primary"
          icon={snap.status === 'playing' ? <PauseOutlined /> : <CaretRightOutlined />}
          onClick={() => player.current?.toggle()}
          disabled={snap.status === 'idle'}
        >
          {snap.status === 'playing' ? 'Pause' : snap.status === 'ended' ? 'Replay' : 'Play'}
        </Button>
        <Select<number>
          aria-label="Playback speed"
          value={snap.speed}
          onChange={(v) => player.current?.setSpeed(v)}
          options={SPEEDS.map((s) => ({ value: s, label: `${String(s)}×` }))}
          style={{ width: 90 }}
        />
        <div className="hp-replay-controls__seek">
          <Slider
            min={0}
            max={Math.max(1, track.durationMs)}
            step={100}
            value={Math.round(position)}
            onChange={(v) => player.current?.seek(v)}
            tooltip={{ formatter: (v) => formatClock(v ?? 0) }}
            ariaLabelForHandle="Seek"
            ariaValueTextFormatterForHandle={(v) => `${formatClock(v)} of ${formatClock(track.durationMs)}`}
          />
        </div>
        <span className="hp-replay-time" aria-live="off">
          {formatClock(position)} / {formatClock(track.durationMs)}
        </span>
      </div>
      {track.kind === 'pty' ? (
        <div className="hp-replay-terminal">
          <TerminalReplay
            handleRef={main}
            pty={pty}
            ariaLabel={`Terminal output replay${track.term ? ` (${track.term})` : ''}${pty ? '' : ' (no PTY)'}`}
            cols={paneSize(track, pty).cols}
            rows={paneSize(track, pty).rows}
          />
        </div>
      ) : (
        <div className="hp-replay-panes hp-replay-panes--exec">
          <div className="hp-replay-pane hp-replay-terminal">
            <h4>stdout</h4>
            <TerminalReplay
              handleRef={main}
              pty={pty}
              ariaLabel="Standard output replay"
              cols={EXEC_PANE.cols}
              rows={EXEC_PANE.rows}
            />
          </div>
          <div className="hp-replay-pane hp-replay-terminal">
            <h4>stderr</h4>
            <TerminalReplay
              handleRef={stderr}
              pty={pty}
              ariaLabel="Standard error replay"
              cols={EXEC_PANE.cols}
              rows={EXEC_PANE.rows}
            />
          </div>
        </div>
      )}
      {exits.length > 0 || notices.length > 0 ? (
        <ul aria-label="Channel events" style={{ margin: 0, paddingLeft: 18 }}>
          {exits.map((e) => (
            <li key={e.seq}>
              {formatClock(e.t)} exit:{' '}
              {e.exit?.signal ? (
                <>
                  signal <code className="hp-mono">{e.exit.signal}</code>
                  {e.exit.coreDumped ? ' (core dumped)' : ''}
                </>
              ) : (
                <>status {String(e.exit?.status ?? '—')}</>
              )}
            </li>
          ))}
          {notices.map((e) => (
            <li key={e.seq}>
              {formatClock(e.t)}{' '}
              {e.kind === 'signal' ? (
                <>
                  signal <code className="hp-mono">{e.signal}</code>
                </>
              ) : (
                <>
                  gateway notice <code className="hp-mono">{e.notice?.code}</code>:{' '}
                  <UntrustedText text={e.notice?.message} source="the gateway recording" />
                </>
              )}
            </li>
          ))}
        </ul>
      ) : null}
    </Space>
  );
}
