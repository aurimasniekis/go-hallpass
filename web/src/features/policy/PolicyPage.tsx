import { EditOutlined, PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Space, Tabs, Tag, type TableColumnsType } from 'antd';
import { useCallback, useState } from 'react';

import { api } from '../../api/client';
import {
  agentsQueryOptions,
  approverRulesQueryOptions,
  operatorsQueryOptions,
  policyRulesQueryOptions,
  policyVersionQueryOptions,
  serversQueryOptions,
} from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { ApproverRule, PolicyRule } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { usePermissions } from '../../lib/usePermissions';
import { useSseState } from '../../stores/sse';
import { EffectiveAccessPreview, LevelBadge } from './EffectiveAccessPreview';
import { limitText } from './ruleForm';
import { ApproverRuleDrawer, RuleDrawer } from './RuleDrawers';
import { summarizeSelector, type SelectorKind } from './selectors/model';

/** Resolves agent/server/operator IDs in selector summaries from lists the operator may read. */
function useIdNames(): (kind: SelectorKind) => (id: string) => string {
  const { can } = usePermissions();
  const agents = useQuery({ ...agentsQueryOptions(), enabled: can('inventory.read') });
  const servers = useQuery({ ...serversQueryOptions(), enabled: can('inventory.read') });
  const operators = useQuery({ ...operatorsQueryOptions(), enabled: can('operators.manage') });
  return useCallback(
    (kind: SelectorKind) => (id: string) => {
      if (kind === 'subject') {
        return agents.data?.items.find((a) => a.id === id)?.name ?? id;
      }
      if (kind === 'target') {
        return servers.data?.items.find((s) => s.id === id)?.alias ?? id;
      }
      if (kind === 'operator') {
        return operators.data?.items.find((o) => o.id === id)?.display_name ?? id;
      }
      return id;
    },
    [agents.data, servers.data, operators.data],
  );
}

const SECONDARY = { color: 'var(--hp-color-text-secondary)' } as const;

function EnabledBadge({ enabled }: { enabled: boolean }) {
  return <StatusBadge tone={enabled ? 'success' : 'neutral'}>{enabled ? 'Enabled' : 'Disabled'}</StatusBadge>;
}

function RulesTab({ canWrite }: { canWrite: boolean }) {
  const rules = useQuery(policyRulesQueryOptions());
  const queryClient = useQueryClient();
  const names = useIdNames();
  const sse = useSseState();
  const [editing, setEditing] = useState<{ rule: PolicyRule | undefined } | null>(null);

  const cols: TableColumnsType<PolicyRule> = [
    {
      key: 'name',
      title: 'Name',
      render: (_v, r) => (
        <>
          <strong>{r.name}</strong>
          {r.description ? <div style={SECONDARY}>{r.description}</div> : null}
        </>
      ),
    },
    {
      key: 'effect',
      title: 'Effect',
      render: (_v, r) =>
        r.effect === 'deny' ? (
          <StatusBadge tone="error">Deny</StatusBadge>
        ) : (
          <LevelBadge level={r.level ?? 'none'} />
        ),
    },
    {
      key: 'subjects',
      title: 'Agents',
      render: (_v, r) => summarizeSelector('subject', r.subjects, names('subject')),
    },
    {
      key: 'targets',
      title: 'Servers',
      render: (_v, r) => summarizeSelector('target', r.targets, names('target')),
    },
    { key: 'roles', title: 'Roles', render: (_v, r) => summarizeSelector('role', r.roles) },
    { key: 'max', title: 'Max', render: (_v, r) => limitText(r.max_duration) },
    { key: 'auto', title: 'Auto up to', render: (_v, r) => limitText(r.auto_max_duration) },
    { key: 'reason', title: 'Reason', render: (_v, r) => (r.require_reason ? <Tag>required</Tag> : '—') },
    { key: 'enabled', title: 'State', render: (_v, r) => <EnabledBadge enabled={r.enabled} /> },
  ];
  if (canWrite) {
    cols.push({
      key: 'actions',
      title: <span className="hp-visually-hidden">Actions</span>,
      render: (_v, r) => (
        <Space size={4}>
          <Button
            size="small"
            icon={<EditOutlined />}
            aria-label={`Edit rule ${r.name}`}
            onClick={() => {
              setEditing({ rule: r });
            }}
          />
          <ConfirmAction
            label="Delete"
            title={`Delete rule “${r.name}”?`}
            description="Access decided by this rule changes immediately. Grants already issued are re-checked by the enforcer."
            confirmLabel="Delete rule"
            buttonProps={{ size: 'small' }}
            onConfirm={() => api.call('delete', '/api/v1/policy/rules/{id}', { path: { id: r.id ?? '' } })}
            onSuccess={() => {
              void queryClient.invalidateQueries({ queryKey: qk.policy });
              void queryClient.invalidateQueries({ queryKey: qk.effectiveAccess });
            }}
          />
        </Space>
      ),
    });
  }

  return (
    <>
      {canWrite ? (
        <div style={{ marginBottom: 12 }}>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setEditing({ rule: undefined });
            }}
          >
            New rule
          </Button>
        </div>
      ) : null}
      <DataTable<PolicyRule>
        caption="Access rules"
        columns={cols}
        rows={rules.data?.items}
        rowKey={(r) => r.id ?? r.name}
        loading={rules.isPending}
        fetching={rules.isFetching}
        error={rules.error}
        onRetry={() => void rules.refetch()}
        stale={sse.status === 'stale' || sse.status === 'disconnected'}
        emptyTitle="No access rules"
        emptyDescription="Without rules, agents see and may request nothing."
      />
      <RuleDrawer
        open={editing !== null}
        rule={editing?.rule}
        onClose={() => {
          setEditing(null);
        }}
      />
    </>
  );
}

function ApproverRulesTab({ canWrite }: { canWrite: boolean }) {
  const rules = useQuery(approverRulesQueryOptions());
  const queryClient = useQueryClient();
  const names = useIdNames();
  const sse = useSseState();
  const [editing, setEditing] = useState<{ rule: ApproverRule | undefined } | null>(null);

  const cols: TableColumnsType<ApproverRule> = [
    {
      key: 'name',
      title: 'Name',
      render: (_v, r) => (
        <>
          <strong>{r.name}</strong>
          {r.description ? <div style={SECONDARY}>{r.description}</div> : null}
        </>
      ),
    },
    {
      key: 'operators',
      title: 'Approvers',
      render: (_v, r) => summarizeSelector('operator', r.operators, names('operator')),
    },
    {
      key: 'targets',
      title: 'Servers',
      render: (_v, r) => summarizeSelector('target', r.targets, names('target')),
    },
    { key: 'roles', title: 'Roles', render: (_v, r) => summarizeSelector('role', r.roles) },
    { key: 'max', title: 'Max approvable', render: (_v, r) => limitText(r.max_duration) },
    { key: 'enabled', title: 'State', render: (_v, r) => <EnabledBadge enabled={r.enabled} /> },
  ];
  if (canWrite) {
    cols.push({
      key: 'actions',
      title: <span className="hp-visually-hidden">Actions</span>,
      render: (_v, r) => (
        <Space size={4}>
          <Button
            size="small"
            icon={<EditOutlined />}
            aria-label={`Edit approver rule ${r.name}`}
            onClick={() => {
              setEditing({ rule: r });
            }}
          />
          <ConfirmAction
            label="Delete"
            title={`Delete approver rule “${r.name}”?`}
            description="Operators matched only by this rule lose approval authority for its scope immediately."
            confirmLabel="Delete approver rule"
            buttonProps={{ size: 'small' }}
            onConfirm={() =>
              api.call('delete', '/api/v1/policy/approver-rules/{id}', { path: { id: r.id ?? '' } })
            }
            onSuccess={() => {
              void queryClient.invalidateQueries({ queryKey: qk.policy });
            }}
          />
        </Space>
      ),
    });
  }

  return (
    <>
      {canWrite ? (
        <div style={{ marginBottom: 12 }}>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => {
              setEditing({ rule: undefined });
            }}
          >
            New approver rule
          </Button>
        </div>
      ) : null}
      <DataTable<ApproverRule>
        caption="Approver rules"
        columns={cols}
        rows={rules.data?.items}
        rowKey={(r) => r.id ?? r.name}
        loading={rules.isPending}
        fetching={rules.isFetching}
        error={rules.error}
        onRetry={() => void rules.refetch()}
        stale={sse.status === 'stale' || sse.status === 'disconnected'}
        emptyTitle="No approver rules"
        emptyDescription="Only administrators can decide requests until approver rules exist."
      />
      <ApproverRuleDrawer
        open={editing !== null}
        rule={editing?.rule}
        onClose={() => {
          setEditing(null);
        }}
      />
    </>
  );
}

/** Policy (docs/PLAN.md §9, HP-POL-*): access rules, approver rules and an effective-access preview. */
export function PolicyPage() {
  const { can, loading } = usePermissions();
  const version = useQuery({ ...policyVersionQueryOptions(), enabled: can('policy.read') });
  if (loading) {
    return null;
  }
  if (!can('policy.read')) {
    return (
      <>
        <PageHeader title="Policy" />
        <PermissionDenied />
      </>
    );
  }
  const canWrite = can('policy.write');
  return (
    <>
      <PageHeader
        title="Policy"
        description="Who may see, request or auto-receive access to which server roles, and who may approve."
        extra={
          <span aria-live="polite">
            Policy version{' '}
            <strong className="hp-mono">
              {version.data ? String(version.data.version) : version.isError ? '?' : '…'}
            </strong>
          </span>
        }
      />
      <Tabs
        items={[
          { key: 'rules', label: 'Access rules', children: <RulesTab canWrite={canWrite} /> },
          { key: 'approvers', label: 'Approver rules', children: <ApproverRulesTab canWrite={canWrite} /> },
          { key: 'preview', label: 'Effective access', children: <EffectiveAccessPreview /> },
        ]}
      />
    </>
  );
}
