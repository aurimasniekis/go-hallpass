import type { TableColumnsType } from 'antd';
import type { ReactNode } from 'react';

import type { Identity, ProviderLink, WebSession } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { StatusBadge } from '../../ds/StatusBadge';
import { revealControls } from '../../ds/untrusted';
import { formatDateTime } from '../../lib/format';

/** Web sessions (operator or self). The user agent is client-provided: control characters are revealed. */
export function WebSessionsTable({
  caption,
  rows,
  loading,
  error,
  onRetry,
  action,
}: {
  caption: string;
  rows: readonly WebSession[] | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  action?: (s: WebSession) => ReactNode;
}) {
  const columns: TableColumnsType<WebSession> = [
    {
      key: 'current',
      title: 'Session',
      render: (_, s) => (s.current ? <StatusBadge tone="info">This session</StatusBadge> : s.auth_method),
    },
    { key: 'method', title: 'Method', dataIndex: 'auth_method' },
    { key: 'created', title: 'Signed in', render: (_, s) => formatDateTime(s.created_at) },
    { key: 'seen', title: 'Last active', render: (_, s) => formatDateTime(s.last_seen_at) },
    { key: 'expires', title: 'Expires', render: (_, s) => formatDateTime(s.expires_at) },
    {
      key: 'ip',
      title: 'IP address',
      render: (_, s) => <span className="hp-mono">{revealControls(s.ip)}</span>,
    },
    {
      key: 'ua',
      title: 'Browser',
      render: (_, s) => {
        const ua = revealControls(s.user_agent);
        return (
          <span
            title={ua}
            style={{
              display: 'inline-block',
              maxWidth: 280,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {ua || '—'}
          </span>
        );
      },
    },
    ...(action
      ? [{ key: 'action', title: 'Actions', render: (_: unknown, s: WebSession) => action(s) }]
      : []),
  ];
  return (
    <DataTable<WebSession>
      caption={caption}
      columns={columns}
      rows={rows}
      rowKey="id"
      loading={loading}
      error={error}
      onRetry={onRetry}
      emptyTitle="No active sessions"
    />
  );
}

/** Linked SSO identities (issuer + subject). */
export function IdentitiesTable({
  caption,
  rows,
  loading,
  error,
  onRetry,
  action,
}: {
  caption: string;
  rows: readonly Identity[] | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  action?: (i: Identity) => ReactNode;
}) {
  const columns: TableColumnsType<Identity> = [
    {
      key: 'issuer',
      title: 'Issuer',
      render: (_, i) => <span className="hp-mono">{revealControls(i.issuer)}</span>,
    },
    {
      key: 'subject',
      title: 'Subject',
      render: (_, i) => <span className="hp-mono">{revealControls(i.subject)}</span>,
    },
    { key: 'via', title: 'Linked via', dataIndex: 'linked_via' },
    { key: 'created', title: 'Linked', render: (_, i) => formatDateTime(i.created_at) },
    { key: 'last', title: 'Last sign-in', render: (_, i) => formatDateTime(i.last_login_at) },
    ...(action ? [{ key: 'action', title: 'Actions', render: (_: unknown, i: Identity) => action(i) }] : []),
  ];
  return (
    <DataTable<Identity>
      caption={caption}
      columns={columns}
      rows={rows}
      rowKey={(i) => `${i.issuer}|${i.subject}`}
      loading={loading}
      error={error}
      onRetry={onRetry}
      emptyTitle="No linked identities"
    />
  );
}

export const CHAT_PROVIDERS = [
  { value: 'slack', label: 'Slack' },
  { value: 'telegram', label: 'Telegram' },
] as const;

export function chatProviderLabel(provider: string): string {
  return CHAT_PROVIDERS.find((p) => p.value === provider)?.label ?? provider;
}

/**
 * Linked chat accounts (Slack/Telegram, HP-NTF-011). Workspace, user ID and display name come from the
 * chat provider, so they are shown with control characters revealed.
 */
export function ProviderLinksTable({
  caption,
  rows,
  loading,
  error,
  onRetry,
  action,
}: {
  caption: string;
  rows: readonly ProviderLink[] | undefined;
  loading: boolean;
  error: unknown;
  onRetry: () => void;
  action?: (l: ProviderLink) => ReactNode;
}) {
  const columns: TableColumnsType<ProviderLink> = [
    { key: 'provider', title: 'Provider', render: (_, l) => chatProviderLabel(l.provider) },
    {
      key: 'workspace',
      title: 'Workspace',
      render: (_, l) => <span className="hp-mono">{revealControls(l.workspace)}</span>,
    },
    {
      key: 'user',
      title: 'User ID',
      render: (_, l) => <span className="hp-mono">{revealControls(l.provider_user_id)}</span>,
    },
    {
      key: 'display',
      title: 'Display name',
      render: (_, l) => (l.display ? revealControls(l.display) : '—'),
    },
    { key: 'via', title: 'Linked via', dataIndex: 'linked_via' },
    { key: 'linked', title: 'Linked', render: (_, l) => formatDateTime(l.linked_at) },
    ...(action
      ? [{ key: 'action', title: 'Actions', render: (_: unknown, l: ProviderLink) => action(l) }]
      : []),
  ];
  return (
    <DataTable<ProviderLink>
      caption={caption}
      columns={columns}
      rows={rows}
      rowKey={(l) => `${l.provider}|${l.workspace}|${l.provider_user_id}`}
      loading={loading}
      error={error}
      onRetry={onRetry}
      emptyTitle="No linked chat accounts"
    />
  );
}
