import { describe, expect, it } from 'vitest';

import type { Integration } from '../../api/types';
import { formToIntegrationBody, integrationToForm, newIntegrationForm, webhookUrl } from './integrationForm';

describe('integration form', () => {
  it('builds a Slack create body with provider, config and only typed secrets', () => {
    const { body, errors } = formToIntegrationBody(
      {
        ...newIntegrationForm('slack'),
        name: ' Ops Slack ',
        team_id: 'T012',
        secrets: { bot_token: ' xoxb-test ', signing_secret: '' },
      },
      'create',
    );
    expect(errors).toEqual([]);
    expect(body).toEqual({
      provider: 'slack',
      name: 'Ops Slack',
      config: { team_id: 'T012' },
      enabled: true,
      secrets: { bot_token: 'xoxb-test' },
    });
  });

  it('omits provider and secrets on update when nothing was typed (keep stored values)', () => {
    const integration: Integration = {
      id: 'int_1',
      provider: 'telegram',
      name: 'TG',
      config: {
        bot_username: 'hallpass_bot',
        allowed_chat_ids: [-1001234, 42],
      } as unknown as Integration['config'],
      secrets_set: ['bot_token', 'webhook_secret'],
      enabled: false,
      version: 4,
      webhook_path: '/hooks/telegram/int_1',
    };
    const form = integrationToForm(integration);
    expect(form.allowed_chat_ids).toEqual(['-1001234', '42']);
    const { body } = formToIntegrationBody(form, 'update');
    expect(body).toEqual({
      name: 'TG',
      config: { bot_username: 'hallpass_bot', allowed_chat_ids: [-1001234, 42] },
      enabled: false,
    });
  });

  it('validates required Slack team and Telegram chat IDs', () => {
    expect(formToIntegrationBody({ ...newIntegrationForm('slack'), name: 'x' }, 'create').errors).toEqual([
      'Slack workspace (team) ID is required, e.g. T0123ABCD.',
    ]);
    const tg = formToIntegrationBody(
      { ...newIntegrationForm('telegram'), name: 'x', bot_username: '@bot', allowed_chat_ids: ['12', 'abc'] },
      'create',
    );
    expect(tg.body).toBeNull();
    expect(tg.errors[0]).toMatch(/"abc" is not a Telegram chat ID/);
  });

  it('strips a leading @ from the Telegram bot username', () => {
    const { body } = formToIntegrationBody(
      { ...newIntegrationForm('telegram'), name: 'x', bot_username: '@hallpass_bot' },
      'create',
    );
    expect(body?.config).toEqual({ bot_username: 'hallpass_bot' });
  });

  it('joins origin and webhook path', () => {
    expect(webhookUrl('https://hp.example/', '/hooks/slack/int_1')).toBe(
      'https://hp.example/hooks/slack/int_1',
    );
  });
});
