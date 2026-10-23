import type { Integration, IntegrationInput, IntegrationProvider } from '../../api/types';

/**
 * Chat integration form state ↔ request bodies (docs/operator/approvals.md, slack.md, telegram.md).
 * Secrets are write-only: the API reports only which ones are stored (`secrets_set`). A blank secret
 * field keeps the stored value, so bodies carry only the secrets the operator typed.
 */

export const SECRET_NAMES: Record<
  IntegrationProvider,
  readonly { name: string; label: string; help: string }[]
> = {
  slack: [
    { name: 'bot_token', label: 'Bot token', help: 'xoxb-… token of the Slack app (chat:write, commands).' },
    { name: 'signing_secret', label: 'Signing secret', help: 'Verifies that callbacks come from Slack.' },
  ],
  telegram: [
    { name: 'bot_token', label: 'Bot token', help: 'Token from @BotFather (123456:ABC…).' },
    {
      name: 'webhook_secret',
      label: 'Webhook secret',
      help: 'Secret token Telegram sends with every update. Generated when left empty on creation.',
    },
  ],
};

export interface IntegrationFormValues {
  provider: IntegrationProvider;
  name: string;
  enabled: boolean;
  team_id: string;
  command: string;
  bot_username: string;
  /** Chat IDs as typed (integers; group chats are negative). */
  allowed_chat_ids: string[];
  secrets: Record<string, string | undefined>;
}

export function newIntegrationForm(provider: IntegrationProvider = 'slack'): IntegrationFormValues {
  return {
    provider,
    name: '',
    enabled: true,
    team_id: '',
    command: '',
    bot_username: '',
    allowed_chat_ids: [],
    secrets: {},
  };
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

export function integrationToForm(integration: Integration): IntegrationFormValues {
  const cfg = (typeof integration.config === 'object' ? integration.config : {}) as Record<string, unknown>;
  const ids = Array.isArray(cfg.allowed_chat_ids) ? cfg.allowed_chat_ids : [];
  return {
    provider: integration.provider,
    name: integration.name,
    enabled: integration.enabled,
    team_id: str(cfg.team_id),
    command: str(cfg.command),
    bot_username: str(cfg.bot_username),
    allowed_chat_ids: ids.filter((v): v is number => typeof v === 'number').map(String),
    secrets: {},
  };
}

export interface IntegrationBuild {
  body: IntegrationInput | null;
  errors: string[];
}

const CHAT_ID = /^-?\d{1,20}$/;

/**
 * Builds the create (`mode: 'create'`) or update body. `provider` is only sent on create (it cannot
 * change). Secrets typed as blank are omitted, keeping the stored value.
 */
export function formToIntegrationBody(
  values: IntegrationFormValues,
  mode: 'create' | 'update',
): IntegrationBuild {
  const errors: string[] = [];
  const name = values.name.trim();
  if (name === '' || name.length > 64) {
    errors.push('Name is required (at most 64 characters).');
  }
  let config: Record<string, unknown>;
  if (values.provider === 'slack') {
    const teamId = values.team_id.trim();
    if (teamId === '' || teamId.length > 32) {
      errors.push('Slack workspace (team) ID is required, e.g. T0123ABCD.');
    }
    config = { team_id: teamId };
    if (values.command.trim() !== '') {
      config.command = values.command.trim();
    }
  } else {
    config = {};
    const username = values.bot_username.trim().replace(/^@/, '');
    if (username !== '') {
      config.bot_username = username;
    }
    const ids: number[] = [];
    for (const raw of values.allowed_chat_ids) {
      const v = raw.trim();
      if (!CHAT_ID.test(v) || !Number.isSafeInteger(Number(v))) {
        errors.push(`"${raw}" is not a Telegram chat ID (an integer; groups are negative).`);
      } else {
        ids.push(Number(v));
      }
    }
    if (ids.length > 100) {
      errors.push('At most 100 allowed chats.');
    }
    if (ids.length) {
      config.allowed_chat_ids = [...new Set(ids)];
    }
  }
  const secrets: Record<string, string> = {};
  for (const s of SECRET_NAMES[values.provider]) {
    const v = values.secrets[s.name]?.trim() ?? '';
    if (v !== '') {
      if (v.length > 512) {
        errors.push(`${s.label} is too long.`);
      }
      secrets[s.name] = v;
    }
  }
  // The spec types `config` as `{type: object}` without properties, which openapi-typescript renders as
  // Record<string, never>; the server accepts the provider-specific shape documented in its description.
  const body: IntegrationInput = {
    name,
    config: config as IntegrationInput['config'],
    enabled: values.enabled,
  };
  if (mode === 'create') {
    body.provider = values.provider;
  }
  if (Object.keys(secrets).length) {
    body.secrets = secrets;
  }
  return { body: errors.length ? null : body, errors };
}

/** Absolute callback URL to register at the provider. */
export function webhookUrl(origin: string, webhookPath: string): string {
  return `${origin.replace(/\/+$/, '')}${webhookPath.startsWith('/') ? '' : '/'}${webhookPath}`;
}
