import { useQuery } from '@tanstack/react-query';
import { Alert, Card, Radio, Select, Space, Table, type TableColumnsType } from 'antd';
import { useState } from 'react';

import {
  agentEffectiveAccessQueryOptions,
  agentsQueryOptions,
  serverEffectiveAccessQueryOptions,
  serversQueryOptions,
} from '../../api/queries';
import type { EffectiveAccessItem } from '../../api/types';
import { EmptyState, ErrorState, LoadingState } from '../../ds/states';
import { StatusBadge, type StatusTone } from '../../ds/StatusBadge';
import { formatDuration } from '../../lib/format';
import { AgentName, RoleName, ServerName } from '../../shared/names';

const LEVEL_DISPLAY: Record<string, [StatusTone, string]> = {
  denied: ['error', 'Denied'],
  none: ['neutral', 'No access'],
  visible: ['info', 'Visible'],
  requestable: ['processing', 'Requestable'],
  auto_approve: ['success', 'Auto-approve'],
};

export function LevelBadge({ level }: { level: string }) {
  const [tone, label] = LEVEL_DISPLAY[level] ?? ['neutral', level];
  return <StatusBadge tone={tone}>{label}</StatusBadge>;
}

function columns(by: 'agent' | 'server'): TableColumnsType<EffectiveAccessItem> {
  return [
    by === 'agent'
      ? {
          key: 'server',
          title: 'Server',
          render: (_v, r) =>
            r.server_alias ? (
              <span title={r.server_id}>{r.server_alias}</span>
            ) : (
              <ServerName id={r.server_id} />
            ),
        }
      : {
          key: 'agent',
          title: 'Agent',
          render: (_v, r) =>
            r.agent_name ? <span title={r.agent_id}>{r.agent_name}</span> : <AgentName id={r.agent_id} />,
        },
    {
      key: 'role',
      title: 'Role',
      render: (_v, r) =>
        r.role_alias ? <span title={r.role_id}>{r.role_alias}</span> : <RoleName id={r.role_id} />,
    },
    { key: 'level', title: 'Level', render: (_v, r) => <LevelBadge level={r.level} /> },
    { key: 'reason', title: 'Reason required', render: (_v, r) => (r.require_reason ? 'Yes' : 'No') },
    {
      key: 'max',
      title: 'Max duration',
      render: (_v, r) => (r.max_duration ? formatDuration(r.max_duration) : '—'),
    },
    {
      key: 'auto',
      title: 'Auto-approve up to',
      render: (_v, r) => (r.auto_max_duration ? formatDuration(r.auto_max_duration) : '—'),
    },
    {
      key: 'rules',
      title: 'Deciding rules',
      render: (_v, r) => (r.rules?.length ? r.rules.join(', ') : '—'),
    },
  ];
}

/**
 * Effective-access preview (HP-POL-009) for one agent or one server under the *current* policy version.
 * Unsaved rule edits are previewed in the rule drawer instead (PolicyChangePreview).
 */
export function EffectiveAccessPreview() {
  const [by, setBy] = useState<'agent' | 'server'>('agent');
  const [id, setId] = useState<string | undefined>(undefined);
  const agents = useQuery({ ...agentsQueryOptions(), enabled: by === 'agent' });
  const servers = useQuery({ ...serversQueryOptions(), enabled: by === 'server' });
  const agentAccess = useQuery({
    ...agentEffectiveAccessQueryOptions(id ?? ''),
    enabled: by === 'agent' && !!id,
  });
  const serverAccess = useQuery({
    ...serverEffectiveAccessQueryOptions(id ?? ''),
    enabled: by === 'server' && !!id,
  });
  const access = by === 'agent' ? agentAccess : serverAccess;
  const list = by === 'agent' ? agents : servers;
  const options =
    by === 'agent'
      ? (agents.data?.items ?? []).map((a) => ({ value: a.id, label: a.name }))
      : (servers.data?.items ?? []).map((s) => ({ value: s.id, label: s.alias }));

  return (
    <Card title="Effective access preview" size="small">
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <p style={{ margin: 0 }}>
          Shows what the saved policy allows right now, with the rules that decided each result. To see how an
          unsaved rule would change this, use Preview changes in the rule editor.
        </p>
        <Space wrap>
          <Radio.Group
            aria-label="Preview by"
            value={by}
            onChange={(e) => {
              setBy(e.target.value as 'agent' | 'server');
              setId(undefined);
            }}
            options={[
              { value: 'agent', label: 'By agent' },
              { value: 'server', label: 'By server' },
            ]}
            optionType="button"
          />
          <Select<string>
            aria-label={by === 'agent' ? 'Agent' : 'Server'}
            placeholder={by === 'agent' ? 'Choose an agent' : 'Choose a server'}
            showSearch={{ optionFilterProp: 'label' }}
            loading={list.isPending && list.fetchStatus !== 'idle'}
            value={id}
            onChange={setId}
            options={options}
            style={{ minWidth: 240 }}
          />
        </Space>
        {list.isError ? <ErrorState error={list.error} /> : null}
        {id === undefined ? (
          <EmptyState title={`Choose ${by === 'agent' ? 'an agent' : 'a server'} to preview`} />
        ) : access.isPending ? (
          <LoadingState label="Evaluating policy…" />
        ) : access.isError ? (
          <ErrorState error={access.error} onRetry={() => void access.refetch()} />
        ) : (
          <>
            <Alert type="info" showIcon title={`Policy version ${String(access.data.policy_version)}`} />
            <Table<EffectiveAccessItem>
              size="small"
              rowKey={(r) => `${r.agent_id}|${r.server_id}|${r.role_id}`}
              columns={columns(by)}
              dataSource={access.data.items}
              pagination={false}
              scroll={{ x: 'max-content' }}
              locale={{ emptyText: <EmptyState title="No roles in scope" /> }}
            />
          </>
        )}
      </Space>
    </Card>
  );
}
