import { describe, expect, it } from 'vitest';

import { channelKind, describeChannelEnd, gatewayExitText, reasonText } from './channelClose';

describe('channel close descriptions', () => {
  it('maps reason codes to words and keeps unknown codes readable', () => {
    expect(reasonText('agent_disconnected')).toBe('Agent disconnected');
    expect(reasonText('failed_before_start')).toBe('Failed before it started');
    expect(reasonText('brand_new_reason')).toBe('Brand new reason');
    expect(reasonText('')).toBeNull();
    expect(reasonText(undefined)).toBeNull();
  });

  it('explains gateway exit codes', () => {
    expect(gatewayExitText(88)).toBe('88 (destination unavailable)');
    expect(gatewayExitText(87)).toBe('87 (access ended)');
    expect(gatewayExitText(99)).toBe('99');
    expect(gatewayExitText(null)).toBeNull();
  });

  it('describes a failed channel and tolerates missing newer fields', () => {
    const failed = describeChannelEnd({
      state: 'failed',
      close_reason: 'failed_before_start',
      close_detail: 'destination refused the login credential',
      gateway_exit_code: 88,
    });
    expect(failed).toEqual({
      reason: 'Failed before it started',
      detail: 'destination refused the login credential',
      gatewayExit: '88 (destination unavailable)',
      exit: null,
      tone: 'error',
    });
    const legacy = describeChannelEnd({ state: 'failed', close_reason: 'failed_before_start' });
    expect(legacy.detail).toBeNull();
    expect(legacy.gatewayExit).toBeNull();
    expect(legacy.reason).toBe('Failed before it started');
    expect(describeChannelEnd({ state: 'active' }).reason).toBeNull();
    const disconnected = describeChannelEnd({
      state: 'closed',
      close_reason: 'agent_disconnected',
      close_detail: 'agent disconnected',
      gateway_exit_code: 87,
    });
    expect(disconnected.detail).toBeNull();
    expect(disconnected.tone).toBe('warning');
    expect(describeChannelEnd({ state: 'closed', close_reason: 'exit', exit_status: 0 }).tone).toBe(
      'neutral',
    );
    expect(describeChannelEnd({ state: 'closed', close_reason: 'exit', exit_status: 2 }).exit).toBe(
      'status 2',
    );
    expect(describeChannelEnd({ state: 'closed', close_detail: 'bad‮detail' }).detail).toBe(
      'bad<U+202E>detail',
    );
  });

  it('names channel kinds with their PTY state', () => {
    expect(channelKind({ kind: 'shell', pty: false })).toBe('shell (no PTY)');
    expect(channelKind({ kind: 'shell', pty: true })).toBe('shell (PTY)');
    expect(channelKind({ kind: 'exec', pty: false })).toBe('exec');
  });
});
