import { Alert, Button } from 'antd';

import { useSseState } from '../stores/sse';
import type { SseState } from '../stores/sse';

export interface ConnectionBannerProps {
  /** Overrides the live store (gallery/tests). */
  state?: SseState;
  onReconnect?: () => void;
}

function since(at: number | null): string {
  return at === null ? '' : ` since ${new Date(at).toLocaleTimeString()}`;
}

/** Live-update status (HP-UI-007 stale/disconnected states). Renders nothing while connected. */
export function ConnectionBanner({ state, onReconnect }: ConnectionBannerProps) {
  const live = useSseState();
  const s = state ?? live;
  const action = onReconnect ? (
    <Button size="small" onClick={onReconnect}>
      Reconnect
    </Button>
  ) : undefined;

  switch (s.status) {
    case 'reconnecting':
      return <Alert banner type="warning" showIcon title="Live updates interrupted. Reconnecting…" />;
    case 'stale':
      return (
        <Alert
          banner
          type="warning"
          showIcon
          title={`Live updates unavailable${since(s.disconnectedAt)}. Data on this page may be out of date.`}
          action={action}
        />
      );
    case 'disconnected':
      return (
        <Alert
          banner
          type="error"
          showIcon
          title={`Live updates disconnected${since(s.disconnectedAt)}. Data will not refresh automatically.`}
          action={action}
        />
      );
    default:
      return null;
  }
}
