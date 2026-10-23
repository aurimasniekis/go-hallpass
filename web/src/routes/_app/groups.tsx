import { createFileRoute, useNavigate } from '@tanstack/react-router';

import type { GroupKind } from '../../api/queries';
import { GROUP_KINDS, GroupsPage } from '../../features/groups/GroupsPage';

interface GroupsSearch {
  kind?: GroupKind;
}

export const Route = createFileRoute('/_app/groups')({
  validateSearch: (search: Record<string, unknown>): GroupsSearch =>
    typeof search.kind === 'string' && (GROUP_KINDS as readonly string[]).includes(search.kind)
      ? { kind: search.kind as GroupKind }
      : {},
  component: GroupsRoute,
});

function GroupsRoute() {
  const { kind } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  return (
    <GroupsPage
      {...(kind ? { kind } : {})}
      onKindChange={(next) => {
        void navigate({ search: next ? { kind: next } : {}, replace: true });
      }}
    />
  );
}
