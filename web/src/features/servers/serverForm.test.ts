import { describe, expect, it } from 'vitest';

import type { Server } from '../../api/types';
import { serverAddress, serverFormValues, toServerInput } from './serverForm';

const base: Server = {
  id: 's1',
  kind: 'ssh',
  alias: 'db1',
  display_name: 'Database 1',
  enabled: true,
  groups: ['db'],
  labels: { env: 'prod' },
  version: 3,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  address_redacted: false,
  address: '10.0.0.5',
  port: 2222,
};

describe('server form mapping', () => {
  it('includes address and port for creates and visible addresses', () => {
    expect(
      toServerInput(
        { alias: ' web ', address: ' 10.0.0.1 ', port: null, labels: ['tier=web'], groups: ['a', 'a'] },
        { includeAddress: true },
      ),
    ).toEqual({
      alias: 'web',
      display_name: 'web',
      description: '',
      environment: '',
      enabled: true,
      groups: ['a'],
      labels: { tier: 'web' },
      metadata: {},
      address: '10.0.0.1',
      port: 22,
    });
  });

  it('omits address fields when the address is redacted and carries the version', () => {
    const body = toServerInput(serverFormValues({ ...base, address_redacted: true, address: '', port: 0 }), {
      includeAddress: false,
      version: 3,
    });
    expect(body).not.toHaveProperty('address');
    expect(body).not.toHaveProperty('port');
    expect(body.version).toBe(3);
  });

  it('formats addresses and hides redacted ones', () => {
    expect(serverAddress(base)).toBe('10.0.0.5:2222');
    expect(serverAddress({ address: 'fd00::1', port: 22, address_redacted: false })).toBe('[fd00::1]:22');
    expect(serverAddress({ address: '', port: 0, address_redacted: true })).toBeNull();
  });
});
