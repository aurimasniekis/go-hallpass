import type { StatusTone } from '../../../ds/StatusBadge';
import { revealControls } from '../../../ds/untrusted';
import {
  formatBytes,
  formatDate,
  formatDateTime,
  formatDuration,
  formatTime,
  parseGoDuration,
} from '../../../lib/format';
import { gatewayExitText, reasonText } from '../../../shared/channelClose';
import { HIDDEN_FIELDS, timelineFields, timelineLabel, timelineProvenance } from './labels';

/**
 * Turns raw timeline events (internal/access/service.go, schema version 1) into one readable sentence per
 * event, grouped by connection and channel. Pure: the component supplies the name lookups it already has.
 * Every value taken from event data is shown as text with control characters revealed; nothing is markup.
 */

export type TimelineCategory =
  | 'request'
  | 'grant'
  | 'connection'
  | 'channel'
  | 'command'
  | 'recording'
  | 'session'
  | 'destination'
  | 'git'
  | 'file'
  | 'other';

export interface TimelineEventInput {
  id: string;
  seq?: number | null | undefined;
  type: string;
  at: string;
  connection_id?: string | undefined;
  channel_id?: string | undefined;
  segment_id?: string | undefined;
  data: unknown;
}

export interface ChannelInfo {
  kind: string;
  pty: boolean;
  connection_id: string;
  git_service?: string | undefined;
  subsystem?: string | undefined;
  api_host?: string | undefined;
}

export interface TimelineContext {
  /** Operator display name for an operator ID, when the page knows it. */
  operatorName?: (id: string) => string | undefined;
  /** Policy rule name for a rule ID, when the page knows it. */
  ruleName?: (id: string) => string | undefined;
  /** The session's channels (kind, PTY and owning connection). */
  channels?: ReadonlyMap<string, ChannelInfo>;
}

export interface TimelineEntry {
  id: string;
  at: string;
  seq: number | null;
  type: string;
  category: TimelineCategory;
  tone: StatusTone;
  /** One human sentence. */
  text: string;
  provenance: 'captured' | 'destination-audit' | null;
  /** 0: session level (request, grant); 1: connection; 2: channel. */
  depth: 0 | 1 | 2;
  /** Short group marker, e.g. `C1` for connection 1 or `C1·2` for its second channel. */
  group: string | null;
  connectionId: string | null;
  channelId: string | null;
  /** Destination record ID (destination.exec), to load the reported command on demand. */
  recordId: string | null;
  /** Raw fields for the expandable "Details" section. */
  details: { key: string; value: string }[];
}

type Data = Record<string, unknown>;

function asData(data: unknown): Data {
  return typeof data === 'object' && data !== null && !Array.isArray(data) ? (data as Data) : {};
}

function str(d: Data, key: string): string | null {
  const v = d[key];
  return typeof v === 'string' && v !== '' ? revealControls(v) : null;
}

function num(d: Data, key: string): number | null {
  const v = d[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

function duration(d: Data): string | null {
  const raw = d.duration;
  if (typeof raw === 'number') {
    return formatDuration(raw);
  }
  if (typeof raw === 'string') {
    const s = parseGoDuration(raw);
    return s === null ? revealControls(raw) : formatDuration(s);
  }
  return null;
}

/** Time of an instant relative to the event: time only on the same day, date and time otherwise. */
function when(iso: string, eventAt: string): string {
  return formatDate(iso) === formatDate(eventAt) ? formatTime(iso) : formatDateTime(iso);
}

/** Lower-cases only the first letter, so revealed `<U+XXXX>` markers keep their case. */
function lowerFirst(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1);
}

function shortKey(id: string): string {
  return id.length > 4 ? `…${id.slice(-4)}` : id;
}

const CHANNEL_ORIGINS: Record<string, string> = {
  web: 'web',
  slack: 'Slack',
  telegram: 'Telegram',
  api: 'API',
  ssh: 'SSH',
};

function decider(d: Data, ctx: TimelineContext): { who: string; via: string | null } {
  const type = str(d, 'actor_type');
  const id = str(d, 'actor_id');
  const channel = str(d, 'channel');
  const via = channel && channel !== 'policy' ? (CHANNEL_ORIGINS[channel] ?? channel) : null;
  if (type === 'policy') {
    const rule = id ? ctx.ruleName?.(id) : undefined;
    return { who: rule ? `policy rule ${rule}` : 'policy', via };
  }
  if (type === 'operator' && id) {
    return { who: ctx.operatorName?.(id) ?? `operator ${shortKey(id)}`, via };
  }
  if (type === 'system') {
    return { who: 'the gateway', via };
  }
  return { who: type ?? 'unknown actor', via };
}

function channelNoun(info: ChannelInfo | undefined, d: Data): string {
  const kind = info?.kind ?? str(d, 'kind');
  const pty = info?.pty ?? (typeof d.pty === 'boolean' ? d.pty : undefined);
  if (kind === 'shell') {
    return pty === false ? 'Shell (no PTY)' : 'Shell';
  }
  if (info?.subsystem === 'sftp') {
    return 'File transfer';
  }
  if (info?.git_service) {
    return 'Git operation';
  }
  if (info?.api_host ?? str(d, 'api_host')) {
    return 'API tunnel';
  }
  if (kind === 'exec') {
    return 'Command';
  }
  return kind ? `${kind[0]?.toUpperCase() ?? ''}${kind.slice(1)} channel` : 'Channel';
}

function exitPart(d: Data): string | null {
  const signal = str(d, 'exit_signal');
  if (signal) {
    return `signal ${signal}`;
  }
  const status = num(d, 'exit_status');
  return status === null ? null : `exit ${String(status)}`;
}

function sentence(ev: TimelineEventInput, d: Data, ctx: TimelineContext, info: ChannelInfo | undefined) {
  const t = ev.type;
  switch (t) {
    case 'request.created': {
      const dur = duration(d);
      return `Access requested${dur ? ` for ${dur}` : ''}${d.has_reason === true ? ' with a reason' : ''}`;
    }
    case 'request.approved':
    case 'request.denied': {
      const { who, via } = decider(d, ctx);
      const dur = duration(d);
      const auto = str(d, 'actor_type') === 'policy';
      const verb =
        t === 'request.approved'
          ? auto
            ? 'Request auto-approved by'
            : 'Request approved by'
          : 'Request denied by';
      return `${verb} ${who}${t === 'request.approved' && dur ? ` for ${dur}` : ''}${via ? ` (${via})` : ''}`;
    }
    case 'request.expired':
      return 'Request expired without a decision';
    case 'request.canceled': {
      const r = reasonText(str(d, 'reason'));
      return `Request canceled${r ? `: ${lowerFirst(r)}` : ''}`;
    }
    case 'grant.activated': {
      const until = str(d, 'expires_at');
      return until ? `Grant active until ${when(until, ev.at)}` : 'Grant activated';
    }
    case 'grant.expired':
      return 'Grant expired';
    case 'grant.revoked': {
      const r = reasonText(str(d, 'reason'));
      return `Grant ended${r ? `: ${lowerFirst(r)}` : ''}`;
    }
    case 'grant.clamped': {
      const until = str(d, 'expires_at');
      return until ? `Grant shortened; now ends at ${when(until, ev.at)}` : 'Grant shortened';
    }
    case 'connection.opened': {
      const key = str(d, 'key_id');
      return `Agent connected${key ? ` (key ${shortKey(key)})` : ''}`;
    }
    case 'connection.closed': {
      const r = str(d, 'reason');
      return r === 'client_closed' || r === null
        ? 'Agent disconnected'
        : `Connection closed: ${lowerFirst(reasonText(r) ?? r)}`;
    }
    case 'exec.requested': {
      const bytes = num(d, 'bytes');
      return `Command requested by the agent${bytes !== null ? ` (${String(bytes)} bytes)` : ''}`;
    }
    case 'channel.opened': {
      const kind = info?.kind ?? str(d, 'kind');
      const pty = info?.pty ?? d.pty === true;
      const cred = str(d, 'credential_kind');
      const using =
        cred === 'certificate' || cred === 'cert'
          ? ' with a certificate'
          : cred === 'key'
            ? ' with the login key'
            : '';
      if (kind === 'shell') {
        return pty
          ? `Interactive shell opened (PTY)${using}`
          : `Shell opened without terminal (no PTY)${using}`;
      }
      if (info?.subsystem === 'sftp') {
        return `File transfer started (SFTP)${using}`;
      }
      if (info?.git_service) {
        return `${GIT_SERVICES[info.git_service] ?? 'Git operation'} started${using}`;
      }
      const apiHost = info?.api_host ?? str(d, 'api_host');
      if (apiHost !== null) {
        return `API tunnel to ${apiHost} opened`;
      }
      if (kind === 'exec') {
        return `Command started${pty ? ' with a PTY' : ''}${using}`;
      }
      return `${channelNoun(info, d)} opened${using}`;
    }
    case 'channel.exited': {
      const reason = str(d, 'reason');
      const exit = exitPart(d);
      const noun = channelNoun(info, d);
      if (reason === 'exit' || reason === null) {
        return `${noun} finished${exit ? ` (${exit})` : ''}`;
      }
      const detail = str(d, 'detail');
      const words = lowerFirst(reasonText(reason) ?? reason);
      const gw = gatewayExitText(num(d, 'gateway_exit_code'));
      const extra = [
        detail && detail.toLowerCase() !== words ? detail : null,
        exit,
        gw ? `gateway exit ${gw}` : null,
      ]
        .filter(Boolean)
        .join('; ');
      return `${noun} ended: ${words}${d.interrupted === true ? ' (interrupted)' : ''}${extra ? ` — ${extra}` : ''}`;
    }
    case 'channel.failed': {
      const detail = str(d, 'detail');
      const reason = reasonText(str(d, 'reason'));
      const gw = gatewayExitText(num(d, 'gateway_exit_code'));
      const why = detail ?? (reason ? lowerFirst(reason) : null) ?? 'unknown reason';
      return `${channelNoun(info, d)} failed: ${why}${gw ? ` — gateway exit ${gw}` : ''}`;
    }
    case 'recording.failed': {
      const err = str(d, 'error');
      return `Recording failed${err ? `: ${err}` : ''}`;
    }
    case 'access_session.closed': {
      const r = reasonText(str(d, 'reason'));
      return `Session closed${r ? `: ${lowerFirst(r)}` : ''}`;
    }
    case 'destination.exec': {
      const pid = num(d, 'pid');
      const uid = num(d, 'uid');
      const meta = [pid !== null ? `pid ${String(pid)}` : null, uid !== null ? `uid ${String(uid)}` : null]
        .filter(Boolean)
        .join(', ');
      const after = d.after_session_end === true ? ' after the session ended' : '';
      return `Destination reported a command${after}${meta ? ` (${meta})` : ''}, unverified`;
    }
    case 'request.approval_recorded': {
      const { who, via } = decider({ ...d, actor_type: 'operator' }, ctx);
      const k = num(d, 'approvals');
      const n = num(d, 'approvals_required');
      const count = k !== null && n !== null ? ` ${String(k)} of ${String(n)}` : '';
      return `Approval${count} recorded by ${who}${via ? ` (${via})` : ''}`;
    }
    case 'git.requested': {
      const svc = str(d, 'service');
      const repo = str(d, 'repo');
      return `${(svc && GIT_SERVICES[svc]) ?? 'Git operation'}${repo ? ` of ${repo}` : ''} requested`;
    }
    case 'git.push':
    case 'git.push_refused': {
      const repo = str(d, 'repo');
      const refs = refList(d.updates);
      if (t === 'git.push') {
        return `Pushed to ${repo ?? 'the repository'}${refs ? `: ${refs}` : ''}`;
      }
      const refused = refList(d.refused, 'reason');
      const err = str(d, 'error');
      return `Push to ${repo ?? 'the repository'} refused${refused ? `: ${refused}` : err ? `: ${err}` : ''}`;
    }
    case 'git.transferred': {
      const sent = num(d, 'bytes_in');
      const got = num(d, 'bytes_out');
      return `Git transfer finished (${formatBytes(sent ?? 0)} sent, ${formatBytes(got ?? 0)} received)`;
    }
    case 'api.request': {
      const method = str(d, 'method') ?? 'request';
      const host = str(d, 'host') ?? '';
      const path = str(d, 'path') ?? '/';
      const query = str(d, 'query');
      const status = num(d, 'status');
      const call = `${method} ${host}${path}${query ? `?${query}` : ''}`;
      const refused = str(d, 'refused');
      if (refused !== null) {
        return `${call} refused (${refused})`;
      }
      return `${call} → ${status ?? '?'} (${formatBytes(num(d, 'bytes_out') ?? 0)})`;
    }
    case 'file.operation': {
      const op = str(d, 'op') ?? 'operation';
      const path = str(d, 'path') ?? '';
      const target = str(d, 'target');
      const bytes = num(d, 'bytes');
      const verb = FILE_OPS[op] ?? op;
      const size = (op === 'read' || op === 'write') && bytes !== null ? ` (${formatBytes(bytes)})` : '';
      const where = `${path}${target ? ` → ${target}` : ''}`;
      if (d.ok !== true) {
        const err = str(d, 'error');
        return `${verb} ${where} failed${err ? `: ${err}` : ''}`;
      }
      return `${verb} ${where}${size}`;
    }
    case 'file.summary': {
      const files = num(d, 'files') ?? 0;
      const read = num(d, 'bytes_read') ?? 0;
      const written = num(d, 'bytes_written') ?? 0;
      const skipped = num(d, 'suppressed_events') ?? 0;
      return `File transfer finished: ${String(files)} file${files === 1 ? '' : 's'}, ${formatBytes(written)} uploaded, ${formatBytes(read)} downloaded${skipped > 0 ? ` (${String(skipped)} further operations not listed)` : ''}`;
    }
    default:
      return timelineLabel(t).label;
  }
}

const GIT_SERVICES: Record<string, string> = {
  'git-upload-pack': 'Clone or fetch',
  'git-receive-pack': 'Push',
  'git-upload-archive': 'Archive download',
};

const FILE_OPS: Record<string, string> = {
  read: 'Downloaded',
  write: 'Uploaded',
  open: 'Opened',
  list: 'Listed',
  remove: 'Removed',
  rename: 'Renamed',
  mkdir: 'Created directory',
  rmdir: 'Removed directory',
  setstat: 'Changed attributes of',
  symlink: 'Created symlink',
  hardlink: 'Created hard link',
};

/** "refs/heads/a (create), refs/heads/b (update)" from a list of ref objects; `extra` names the annotation field. */
function refList(v: unknown, extra = 'action'): string {
  if (!Array.isArray(v)) {
    return '';
  }
  return v
    .slice(0, 5)
    .map((u: unknown) => {
      const o = asData(u);
      const ref = str(o, 'ref') ?? '?';
      const note = str(o, extra);
      return note ? `${ref} (${note})` : ref;
    })
    .join(', ')
    .concat(v.length > 5 ? `, and ${String(v.length - 5)} more` : '');
}

function category(type: string): TimelineCategory {
  if (type === 'exec.requested') {
    return 'command';
  }
  if (type === 'destination.exec') {
    return 'destination';
  }
  if (type === 'access_session.closed') {
    return 'session';
  }
  const head = type.split('.')[0] ?? '';
  return (
    (['request', 'grant', 'connection', 'channel', 'recording', 'git', 'file'] as const).find(
      (c) => c === head,
    ) ?? 'other'
  );
}

function tone(type: string, d: Data): StatusTone {
  if (type === 'channel.exited') {
    const reason = d.reason;
    if (typeof reason === 'string' && reason !== 'exit') {
      return 'warning';
    }
    return (typeof d.exit_status === 'number' && d.exit_status !== 0) || typeof d.exit_signal === 'string'
      ? 'warning'
      : 'neutral';
  }
  if (type === 'connection.closed' || type === 'access_session.closed') {
    return 'neutral';
  }
  if (type === 'file.operation') {
    return d.ok === true ? (d.op === 'remove' || d.op === 'rmdir' ? 'warning' : 'info') : 'error';
  }
  if (type === 'api.request') {
    const status = typeof d.status === 'number' ? d.status : 0;
    return d.refused !== undefined || status >= 400
      ? 'error'
      : d.method === 'GET' || d.method === 'HEAD'
        ? 'info'
        : 'warning';
  }
  return timelineLabel(type).tone;
}

/** Hidden from Details: never shown (`verified` would only mislead) or already resolved in the sentence. */
const DETAIL_HIDDEN: ReadonlySet<string> = HIDDEN_FIELDS;

/**
 * Describes and groups events. Input order is preserved (callers sort by sequence). Connections are
 * numbered in order of appearance (`C1`, `C2`), their channels within them (`C1·1`, `C1·2`).
 */
export function describeTimeline(
  events: readonly TimelineEventInput[],
  ctx: TimelineContext = {},
): TimelineEntry[] {
  const connNo = new Map<string, number>();
  const chanNo = new Map<string, string>();
  const chanCount = new Map<string, number>();
  const connLabel = (id: string): string => {
    let n = connNo.get(id);
    if (n === undefined) {
      n = connNo.size + 1;
      connNo.set(id, n);
    }
    return `C${String(n)}`;
  };
  const chanLabel = (channelId: string, connectionId: string | null): string => {
    const known = chanNo.get(channelId);
    if (known) {
      return known;
    }
    let label: string;
    if (connectionId) {
      const c = connLabel(connectionId);
      const k = (chanCount.get(connectionId) ?? 0) + 1;
      chanCount.set(connectionId, k);
      label = `${c}·${String(k)}`;
    } else {
      label = `ch${String(chanNo.size + 1)}`;
    }
    chanNo.set(channelId, label);
    return label;
  };

  return events.map((ev) => {
    const d = asData(ev.data);
    const info = ev.channel_id ? ctx.channels?.get(ev.channel_id) : undefined;
    const connectionId = ev.connection_id ?? info?.connection_id ?? null;
    const channelId = ev.channel_id ?? null;
    let depth: 0 | 1 | 2 = 0;
    let group: string | null = null;
    if (channelId) {
      depth = 2;
      group = chanLabel(channelId, connectionId);
    } else if (connectionId) {
      depth = 1;
      group = connLabel(connectionId);
    }
    const details = timelineFields(ev.data).filter((f) => !DETAIL_HIDDEN.has(f.key));
    const ids: { key: string; value: string }[] = [];
    if (ev.seq !== null && ev.seq !== undefined) {
      ids.push({ key: 'seq', value: String(ev.seq) });
    }
    ids.push({ key: 'type', value: revealControls(ev.type) });
    ids.push({ key: 'at', value: ev.at });
    if (connectionId) {
      ids.push({ key: 'connection_id', value: connectionId });
    }
    if (channelId) {
      ids.push({ key: 'channel_id', value: channelId });
    }
    if (ev.segment_id) {
      ids.push({ key: 'segment_id', value: ev.segment_id });
    }
    ids.push({ key: 'event_id', value: ev.id });
    const recordId = ev.type === 'destination.exec' ? str(d, 'record_id') : null;
    return {
      id: ev.id,
      at: ev.at,
      seq: ev.seq ?? null,
      type: ev.type,
      category: category(ev.type),
      tone: tone(ev.type, d),
      text: sentence(ev, d, ctx, info),
      provenance: timelineProvenance(ev.type),
      depth,
      group,
      connectionId,
      channelId,
      recordId,
      details: [...details, ...ids],
    };
  });
}
