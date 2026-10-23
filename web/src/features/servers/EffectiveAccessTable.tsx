import { useQuery } from '@tanstack/react-query';
import { Card, Space, Table, Tag } from 'antd';

import {
  agentEffectiveAccessQueryOptions,
  policyRulesQueryOptions,
  serverEffectiveAccessQueryOptions,
} from '../../api/queries';
import type { EffectiveAccessItem } from '../../api/types';
import { EmptyState, ErrorState, LoadingState } from '../../ds/states';
import { StatusBadge, type StatusTone } from '../../ds/StatusBadge';
import { formatDuration } from '../../lib/format';
import { AgentName, RoleName, ServerName } from '../../shared/names';

const LEVELS: Record<string, [StatusTone, string]> = {
  visible: ['info', 'Visible'],
  requestable: ['processing', 'Requestable'],
  auto_approve: ['success', 'Auto-approve'],
  denied: ['error', 'Denied'],
  none: ['neutral', 'No access'],
};

export function levelDisplay(level: string): [StatusTone, string] {
  return LEVELS[level] ?? ['neutral', level];
}

/**
 * Effective-access preview (HP-POL-009) for one agent or one server: what policy currently allows, with
 * the deciding rules. Read-only; computed by the server from the current policy snapshot.
 */
export function EffectiveAccessCard({ kind, id }: { kind: 'agent' | 'server'; id: string }) {
  const agentQuery = useQuery({ ...agentEffectiveAccessQueryOptions(id), enabled: kind === 'agent' });
  const serverQuery = useQuery({ ...serverEffectiveAccessQueryOptions(id), enabled: kind === 'server' });
  const query = kind === 'agent' ? agentQuery : serverQuery;
  // Rule IDs are resolved to names when the caller can read policy (this card needs policy.read anyway).
  const rules = useQuery(policyRulesQueryOptions());
  const ruleNames = new Map((rules.data?.items ?? []).map((r) => [r.id ?? '', r.name]));
  const columns = [
    kind === 'agent'
      ? {
          key: 'server',
          title: 'Server',
          render: (_: unknown, r: EffectiveAccessItem) => (
            <span title={r.server_id}>{r.server_alias ?? <ServerName id={r.server_id} />}</span>
          ),
        }
      : {
          key: 'agent',
          title: 'Agent',
          render: (_: unknown, r: EffectiveAccessItem) => (
            <span title={r.agent_id}>{r.agent_name ?? <AgentName id={r.agent_id} />}</span>
          ),
        },
    {
      key: 'role',
      title: 'Role',
      render: (_: unknown, r: EffectiveAccessItem) =>
        r.role_alias ? <span title={r.role_id}>{r.role_alias}</span> : <RoleName id={r.role_id} />,
    },
    {
      key: 'level',
      title: 'Level',
      render: (_: unknown, r: EffectiveAccessItem) => {
        const [tone, label] = levelDisplay(r.level);
        return <StatusBadge tone={tone}>{label}</StatusBadge>;
      },
    },
    {
      key: 'reason',
      title: 'Reason required',
      render: (_: unknown, r: EffectiveAccessItem) => (r.require_reason ? 'Yes' : 'No'),
    },
    {
      key: 'max',
      title: 'Max duration',
      render: (_: unknown, r: EffectiveAccessItem) => (r.max_duration ? formatDuration(r.max_duration) : '—'),
    },
    {
      key: 'auto',
      title: 'Auto-approve up to',
      render: (_: unknown, r: EffectiveAccessItem) =>
        r.auto_max_duration ? formatDuration(r.auto_max_duration) : '—',
    },
    {
      key: 'rules',
      title: 'Deciding rules',
      render: (_: unknown, r: EffectiveAccessItem) =>
        r.rules && r.rules.length > 0 ? (
          <Space size={4} wrap>
            {r.rules.map((rule) => (
              <Tag key={rule} title={rule}>
                {ruleNames.get(rule) ?? rule}
              </Tag>
            ))}
          </Space>
        ) : (
          '—'
        ),
    },
  ];
  return (
    <Card
      size="small"
      title="Effective access"
      extra={query.data ? <span>Policy version {query.data.policy_version}</span> : null}
    >
      {query.isPending ? (
        <LoadingState />
      ) : query.isError ? (
        <ErrorState error={query.error} onRetry={() => void query.refetch()} />
      ) : query.data.items.length === 0 ? (
        <EmptyState
          title="No access"
          description="No policy rule makes any role visible for this combination."
        />
      ) : (
        <Table<EffectiveAccessItem>
          size="small"
          pagination={false}
          rowKey={(r) => `${r.agent_id}|${r.server_id}|${r.role_id}`}
          columns={columns}
          dataSource={query.data.items}
          scroll={{ x: 'max-content' }}
          aria-label="Effective access"
        />
      )}
    </Card>
  );
}
