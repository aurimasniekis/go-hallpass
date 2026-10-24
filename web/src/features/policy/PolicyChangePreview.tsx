import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Card, Radio, Select, Space, Table } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { agentsQueryOptions, serversQueryOptions } from '../../api/queries';
import type { EffectiveAccessItem } from '../../api/types';
import { LevelBadge } from './EffectiveAccessPreview';
import type { RuleBody } from './ruleForm';

interface Change {
  key: string;
  target: string;
  role: string;
  before: string;
  after: string;
}

function label(r: EffectiveAccessItem, by: 'agent' | 'server'): string {
  return by === 'agent' ? (r.server_alias ?? r.server_id) : (r.agent_name ?? r.agent_id);
}

/** Rows whose level differs between the stored policy and the proposed change. */
export function diffAccess(
  before: EffectiveAccessItem[],
  after: EffectiveAccessItem[],
  by: 'agent' | 'server',
): Change[] {
  const key = (r: EffectiveAccessItem) => `${r.agent_id}|${r.server_id}|${r.role_id}`;
  const prev = new Map(before.map((r) => [key(r), r]));
  const next = new Map(after.map((r) => [key(r), r]));
  const out: Change[] = [];
  for (const k of new Set([...prev.keys(), ...next.keys()])) {
    const b = prev.get(k);
    const a = next.get(k);
    const r = a ?? b;
    const bl = b?.level ?? 'none';
    const al = a?.level ?? 'none';
    if (r && bl !== al) {
      out.push({ key: k, target: label(r, by), role: r.role_alias ?? r.role_id, before: bl, after: al });
    }
  }
  return out.sort((x, y) => x.target.localeCompare(y.target) || x.role.localeCompare(y.role));
}

/**
 * What-if preview of an unsaved rule (HP-POL-009): how effective access of one agent or server would change.
 * Nothing is saved; the server evaluates the proposed rule set.
 */
export function PolicyChangePreview({
  build,
  ruleId,
}: {
  build: () => RuleBody | null;
  ruleId: string | undefined;
}) {
  const [by, setBy] = useState<'agent' | 'server'>('agent');
  const [id, setId] = useState<string | undefined>(undefined);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [changes, setChanges] = useState<Change[] | null>(null);
  const agents = useQuery({ ...agentsQueryOptions(), enabled: by === 'agent' });
  const servers = useQuery({ ...serversQueryOptions(), enabled: by === 'server' });
  const options =
    by === 'agent'
      ? (agents.data?.items ?? []).map((a) => ({ value: a.id, label: a.name }))
      : (servers.data?.items ?? []).map((s) => ({ value: s.id, label: s.alias }));

  const run = async () => {
    const body = build();
    if (!body || !id) {
      return;
    }
    setPending(true);
    setError(null);
    try {
      const res = await api.call('post', '/api/v1/policy/preview', {
        body: {
          rule: { ...body, ...(ruleId ? { id: ruleId } : {}) },
          ...(by === 'agent' ? { agent_id: id } : { server_id: id }),
        },
      });
      setChanges(diffAccess(res.before.items, res.after.items, by));
    } catch (e) {
      setError(e);
      setChanges(null);
    } finally {
      setPending(false);
    }
  };

  return (
    <Card size="small" title="Preview changes" style={{ marginBottom: 16 }}>
      <Space wrap style={{ marginBottom: 12 }}>
        <Radio.Group
          value={by}
          onChange={(e) => {
            setBy(e.target.value as 'agent' | 'server');
            setId(undefined);
            setChanges(null);
          }}
          optionType="button"
          options={[
            { value: 'agent', label: 'For an agent' },
            { value: 'server', label: 'For a server' },
          ]}
        />
        <Select
          showSearch={{ optionFilterProp: 'label' }}
          placeholder={by === 'agent' ? 'Choose an agent' : 'Choose a server'}
          aria-label={by === 'agent' ? 'Preview agent' : 'Preview server'}
          style={{ minWidth: 220 }}
          value={id}
          options={options}
          onChange={(v: string) => {
            setId(v);
            setChanges(null);
          }}
        />
        <Button onClick={() => void run()} loading={pending} disabled={!id}>
          Preview
        </Button>
      </Space>
      {error !== null ? <Alert type="error" showIcon title={errorMessage(error)} /> : null}
      {changes !== null && changes.length === 0 ? (
        <Alert type="info" showIcon title="This change does not alter effective access here." />
      ) : null}
      {changes !== null && changes.length > 0 ? (
        <Table<Change>
          size="small"
          pagination={false}
          rowKey="key"
          dataSource={changes}
          aria-label="Access changes"
          columns={[
            { key: 'target', title: by === 'agent' ? 'Server' : 'Agent', dataIndex: 'target' },
            { key: 'role', title: 'Role', dataIndex: 'role' },
            { key: 'before', title: 'Now', render: (_v, c) => <LevelBadge level={c.before} /> },
            { key: 'after', title: 'With this change', render: (_v, c) => <LevelBadge level={c.after} /> },
          ]}
        />
      ) : null}
    </Card>
  );
}
