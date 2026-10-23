import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';

import {
  agentsQueryOptions,
  operatorsQueryOptions,
  roleQueryOptions,
  serversQueryOptions,
} from '../api/queries';
import { shortId } from '../lib/format';
import { usePermissions } from '../lib/usePermissions';

/**
 * Resolve resource IDs to operator-assigned names (agent name, server alias, role alias). Lookups use
 * cached list/detail queries and fall back to the shortened ID when the caller lacks permission or the
 * resource is gone. Names are operator configuration, rendered as plain text.
 */

function IdFallback({ id }: { id: string }) {
  return (
    <code className="hp-mono" title={id}>
      {shortId(id)}
    </code>
  );
}

export function AgentName({ id, link = true }: { id: string | null | undefined; link?: boolean }) {
  const { can } = usePermissions();
  const agents = useQuery({ ...agentsQueryOptions(), enabled: can('inventory.read') });
  if (!id) {
    return <>—</>;
  }
  const name = agents.data?.items.find((a) => a.id === id)?.name;
  const content = name ? <span title={id}>{name}</span> : <IdFallback id={id} />;
  return link && can('inventory.read') ? (
    <Link to="/agents/$id" params={{ id }}>
      {content}
    </Link>
  ) : (
    content
  );
}

export function ServerName({ id, link = true }: { id: string | null | undefined; link?: boolean }) {
  const { can } = usePermissions();
  const servers = useQuery({ ...serversQueryOptions(), enabled: can('inventory.read') });
  if (!id) {
    return <>—</>;
  }
  const server = servers.data?.items.find((s) => s.id === id);
  const content = server ? (
    <span title={server.display_name || id}>{server.alias}</span>
  ) : (
    <IdFallback id={id} />
  );
  return link && can('inventory.read') ? (
    <Link to="/servers/$id" params={{ id }}>
      {content}
    </Link>
  ) : (
    content
  );
}

export function RoleName({ id, link = true }: { id: string | null | undefined; link?: boolean }) {
  const { can } = usePermissions();
  const role = useQuery({ ...roleQueryOptions(id ?? ''), enabled: Boolean(id) && can('inventory.read') });
  if (!id) {
    return <>—</>;
  }
  const content = role.data ? <span title={id}>{role.data.alias}</span> : <IdFallback id={id} />;
  return link && can('inventory.read') ? (
    <Link to="/roles/$id" params={{ id }}>
      {content}
    </Link>
  ) : (
    content
  );
}

export function OperatorName({ id, link = true }: { id: string | null | undefined; link?: boolean }) {
  const { can, me } = usePermissions();
  const operators = useQuery({ ...operatorsQueryOptions(), enabled: can('operators.manage') });
  if (!id) {
    return <>—</>;
  }
  const name =
    me?.operator.id === id
      ? me.operator.display_name
      : operators.data?.items.find((o) => o.id === id)?.display_name;
  const content = name ? <span title={id}>{name}</span> : <IdFallback id={id} />;
  return link && can('operators.manage') ? (
    <Link to="/operators/$id" params={{ id }}>
      {content}
    </Link>
  ) : (
    content
  );
}
