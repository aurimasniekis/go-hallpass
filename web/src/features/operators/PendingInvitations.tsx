import { useQuery, useQueryClient } from '@tanstack/react-query';
import { App, Card } from 'antd';

import { api } from '../../api/client';
import { qk } from '../../api/queryKeys';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { DataTable } from '../../ds/DataTable';
import { formatDateTime } from '../../lib/format';
import { roleLabel } from './roles';

/** Query key: nested under the operators key, so creating an invitation (which refreshes operators) refreshes it too. */
export const invitationsKey = [...qk.operators, 'invitations'] as const;

interface Invitation {
  id: string;
  email: string;
  roles: string[];
  expires_at: string;
  created_at: string;
  created_by: string;
}

/**
 * Pending invitations (HP-AUTH-011): the token is never shown again; revoking makes the link unusable. Revocation is
 * audited and needs recent authentication (the reauth prompt appears when required).
 */
export function PendingInvitations() {
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const invitations = useQuery({
    queryKey: invitationsKey,
    queryFn: async () => (await api.call('get', '/api/v1/invitations')).items as Invitation[],
  });
  return (
    <Card title="Pending invitations" style={{ marginTop: 16 }}>
      <DataTable<Invitation>
        caption="Pending invitations"
        rows={invitations.data}
        rowKey="id"
        loading={invitations.isPending}
        fetching={invitations.isFetching}
        error={invitations.error}
        onRetry={() => void invitations.refetch()}
        emptyTitle="No pending invitations"
        emptyDescription="Invitations appear here until they are accepted, expire or are revoked."
        columns={[
          { key: 'email', title: 'Email', render: (_v, i) => i.email },
          {
            key: 'roles',
            title: 'Roles',
            render: (_v, i) => (i.roles.length ? i.roles.map(roleLabel).join(', ') : 'No roles'),
          },
          { key: 'created', title: 'Created', render: (_v, i) => formatDateTime(i.created_at) },
          { key: 'expires', title: 'Expires', render: (_v, i) => formatDateTime(i.expires_at) },
          {
            key: 'actions',
            title: <span className="hp-visually-hidden">Actions</span>,
            align: 'right',
            render: (_v, i) => (
              <ConfirmAction<undefined>
                label="Revoke"
                title={`Revoke the invitation for ${i.email}?`}
                confirmLabel="Revoke"
                buttonProps={{ size: 'small', 'aria-label': `Revoke invitation for ${i.email}` }}
                description="The invitation link stops working immediately. Send a new invitation if needed."
                onConfirm={async () => {
                  await api.call('delete', '/api/v1/invitations/{id}', { path: { id: i.id } });
                  return undefined;
                }}
                onSuccess={() => {
                  void message.success(`Invitation for ${i.email} revoked`);
                  void queryClient.invalidateQueries({ queryKey: invitationsKey });
                }}
              />
            ),
          },
        ]}
      />
    </Card>
  );
}
