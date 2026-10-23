import { useQuery } from '@tanstack/react-query';
import { Card, Radio, Space } from 'antd';

import { groupsQueryOptions, type GroupKind } from '../../api/queries';
import type { Group } from '../../api/types';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { PermissionDenied } from '../../ds/states';
import { usePermissions } from '../../lib/usePermissions';
import { useSseState } from '../../stores/sse';

export const GROUP_KINDS: readonly GroupKind[] = ['agent', 'server', 'operator'];

const KIND_LABEL: Record<string, string> = { agent: 'Agent', server: 'Server', operator: 'Operator' };

/**
 * Groups (read-only). Groups exist because something was assigned to them (agents, servers, operators or
 * SSO group mappings); they are used by policy selectors.
 */
export function GroupsPage({
  kind,
  onKindChange,
}: {
  kind?: GroupKind;
  onKindChange: (kind?: GroupKind) => void;
}) {
  const { can, loading } = usePermissions();
  const query = useQuery({ ...groupsQueryOptions(kind), enabled: can('inventory.read') });
  const sse = useSseState();

  if (!loading && !can('inventory.read')) {
    return (
      <>
        <PageHeader title="Groups" />
        <PermissionDenied />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Groups"
        description="Groups are created when an agent, server or operator is first assigned to them, and are used by policy selectors."
      />
      <Card size="small">
        <Space style={{ marginBottom: 12 }}>
          <Radio.Group
            aria-label="Group kind"
            optionType="button"
            value={kind ?? 'all'}
            onChange={(e) => {
              const v = e.target.value as string;
              onKindChange(v === 'all' ? undefined : (v as GroupKind));
            }}
            options={[
              { value: 'all', label: 'All' },
              ...GROUP_KINDS.map((k) => ({ value: k, label: `${KIND_LABEL[k] ?? k}s` })),
            ]}
          />
        </Space>
        <DataTable<Group>
          caption="Groups"
          rowKey="id"
          rows={query.data?.items}
          loading={query.isPending}
          fetching={query.isFetching}
          error={query.error}
          onRetry={() => void query.refetch()}
          stale={sse.status === 'stale' || sse.status === 'disconnected'}
          emptyTitle="No groups"
          emptyDescription="Assign a group to an agent, server or operator to create it."
          columns={[
            { key: 'name', title: 'Name', dataIndex: 'name' },
            { key: 'kind', title: 'Kind', render: (_, g) => KIND_LABEL[g.kind] ?? g.kind },
            { key: 'id', title: 'ID', render: (_, g) => <code className="hp-mono">{g.id}</code> },
          ]}
        />
      </Card>
    </>
  );
}
