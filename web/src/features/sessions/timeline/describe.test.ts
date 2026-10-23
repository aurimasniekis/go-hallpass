import { describe, expect, it } from 'vitest';

import { formatTime } from '../../../lib/format';
import { describeTimeline, type ChannelInfo, type TimelineEventInput } from './describe';

const at = '2026-10-23T22:55:54Z';
let n = 0;
function ev(
  type: string,
  data: Record<string, unknown>,
  extra: Partial<TimelineEventInput> = {},
): TimelineEventInput {
  n += 1;
  return { id: `evt_${String(n)}`, seq: n, type, at, data, ...extra };
}

const channels = new Map<string, ChannelInfo>([
  ['chn_exec', { kind: 'exec', pty: false, connection_id: 'con_1' }],
  ['chn_shell', { kind: 'shell', pty: false, connection_id: 'con_1' }],
  ['chn_pty', { kind: 'shell', pty: true, connection_id: 'con_2' }],
]);

describe('describeTimeline', () => {
  it('writes one human sentence per event with names resolved from page data', () => {
    const out = describeTimeline(
      [
        ev('request.approved', {
          actor_type: 'operator',
          actor_id: 'opr_1',
          channel: 'web',
          duration: '30m0s',
        }),
        ev('grant.activated', { grant_id: 'grt_1', starts_at: at, expires_at: '2026-10-23T23:25:54Z' }),
        ev('connection.opened', { key_id: 'key_01m5nfk2ckesxtsa4r89awtcdx' }, { connection_id: 'con_1' }),
        ev('exec.requested', { bytes: 82, has_command: true }, { channel_id: 'chn_exec' }),
        ev(
          'channel.opened',
          { kind: 'shell', pty: false, credential_kind: 'key' },
          { channel_id: 'chn_shell' },
        ),
        ev(
          'channel.exited',
          { reason: 'agent_disconnected', gateway_exit_code: 87 },
          { channel_id: 'chn_shell' },
        ),
        ev('channel.exited', { reason: 'exit', exit_status: 0 }, { channel_id: 'chn_exec' }),
        ev('recording.failed', { error: 'recording write failed' }, { channel_id: 'chn_exec' }),
        ev('connection.closed', { reason: 'client_closed' }, { connection_id: 'con_1' }),
      ],
      { channels, operatorName: (id) => (id === 'opr_1' ? 'Demo Admin' : undefined) },
    );
    expect(out.map((e) => e.text)).toEqual([
      'Request approved by Demo Admin for 30m (web)',
      `Grant active until ${formatTime('2026-10-23T23:25:54Z')}`,
      'Agent connected (key …tcdx)',
      'Command requested by the agent (82 bytes)',
      'Shell opened without terminal (no PTY) with the login key',
      'Shell (no PTY) ended: agent disconnected — gateway exit 87 (access ended)',
      'Command finished (exit 0)',
      'Recording failed: recording write failed',
      'Agent disconnected',
    ]);
    expect(out.map((e) => e.tone)).toEqual([
      'success',
      'success',
      'info',
      'info',
      'success',
      'warning',
      'neutral',
      'error',
      'neutral',
    ]);
  });

  it('groups channel events under their connection', () => {
    const out = describeTimeline(
      [
        ev('request.created', { duration: '1h0m0s', has_reason: true }),
        ev('connection.opened', {}, { connection_id: 'con_1' }),
        ev('channel.opened', { kind: 'exec' }, { channel_id: 'chn_exec' }),
        ev('connection.opened', {}, { connection_id: 'con_2' }),
        ev('channel.opened', { kind: 'shell', pty: true }, { channel_id: 'chn_pty' }),
        ev('channel.opened', { kind: 'shell' }, { channel_id: 'chn_shell' }),
      ],
      { channels },
    );
    expect(out.map((e) => [e.depth, e.group])).toEqual([
      [0, null],
      [1, 'C1'],
      [2, 'C1·1'],
      [1, 'C2'],
      [2, 'C2·1'],
      [2, 'C1·2'],
    ]);
    expect(out[0]?.text).toBe('Access requested for 1h with a reason');
    expect(out[4]?.text).toBe('Interactive shell opened (PTY)');
    // Channel events carry the connection resolved from the channel list.
    expect(out[2]?.connectionId).toBe('con_1');
  });

  it('explains gateway failures with the classified detail and exit code', () => {
    const [failed] = describeTimeline(
      [
        ev(
          'channel.failed',
          { reason: 'failed_before_start', detail: 'destination host key changed', gateway_exit_code: 88 },
          { channel_id: 'chn_exec' },
        ),
      ],
      { channels },
    );
    expect(failed?.text).toBe(
      'Command failed: destination host key changed — gateway exit 88 (destination unavailable)',
    );
    expect(failed?.tone).toBe('error');
    // Older events without a detail still say something useful.
    const [old] = describeTimeline([ev('channel.failed', { reason: 'failed_before_start' })]);
    expect(old?.text).toBe('Channel failed: failed before it started');
  });

  it('labels policy decisions with the rule name', () => {
    const [e] = describeTimeline(
      [
        ev('request.approved', {
          actor_type: 'policy',
          actor_id: 'pol_1',
          channel: 'policy',
          duration: '30m0s',
        }),
      ],
      { ruleName: () => 'sre-inspect-auto' },
    );
    expect(e?.text).toBe('Request auto-approved by policy rule sre-inspect-auto for 30m');
  });

  it('keeps destination.exec destination-reported and never verified', () => {
    const [e] = describeTimeline([
      ev(
        'destination.exec',
        { provenance: 'destination-audit', verified: false, pid: 42, uid: 1000, record_id: 'drc_1' },
        { connection_id: 'con_1' },
      ),
    ]);
    expect(e?.text).toBe('Destination reported a command (pid 42, uid 1000), unverified');
    expect((e?.text ?? '').replace(/unverified/g, '')).not.toMatch(/verified/i);
    expect(e?.provenance).toBe('destination-audit');
    expect(e?.recordId).toBe('drc_1');
    expect(e?.details.map((d) => d.key)).not.toContain('verified');
    expect(e?.details.map((d) => d.key)).not.toContain('provenance');
  });

  it('reveals control characters in data and never drops unknown events', () => {
    const [unknown, reason] = describeTimeline([
      ev('future.thing', { a: 1 }),
      ev('access_session.closed', { reason: 'odd‮code' }),
    ]);
    expect(unknown?.text).toBe('future.thing');
    expect(unknown?.category).toBe('other');
    expect(reason?.text).toBe('Session closed: odd<U+202E>code');
    expect(unknown?.details.find((d) => d.key === 'a')?.value).toBe('1');
  });
});
