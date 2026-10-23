import { describe, expect, it } from 'vitest';

import { linkInstruction } from './chatLink';

describe('linkInstruction', () => {
  it('uses the Slack slash command', () => {
    expect(linkInstruction('slack', 'ABC123').command).toBe('/hallpass link ABC123');
  });

  it('uses /link in a private Telegram chat and warns about groups', () => {
    const t = linkInstruction('telegram', 'XYZ');
    expect(t.command).toBe('/link XYZ');
    expect(t.where).toMatch(/private chat/);
    expect(t.caution).toMatch(/burned/);
  });
});
