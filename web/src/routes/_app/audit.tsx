import { createFileRoute, useNavigate } from '@tanstack/react-router';

import { AuditPage } from '../../features/audit/AuditPage';
import { parseAuditSearch, type AuditSearch } from '../../features/audit/auditFilters';

export const Route = createFileRoute('/_app/audit')({
  validateSearch: (search: Record<string, unknown>): AuditSearch => parseAuditSearch(search),
  component: AuditRoute,
});

function AuditRoute() {
  const search = Route.useSearch();
  const navigate = useNavigate();
  return (
    <AuditPage
      search={search}
      onSearchChange={(next) => {
        void navigate({ to: '/audit', search: next });
      }}
    />
  );
}
