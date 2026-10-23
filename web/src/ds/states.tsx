import { Alert, Button, Empty, Result, Spin } from 'antd';
import type { ReactNode } from 'react';

import { errorMessage, isApiError } from '../api/errors';

/**
 * Shared data-view states (HP-UI-007): loading, empty, error, permission-denied and not-implemented.
 * Every data view must render one of these instead of placeholder or fake data.
 */

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" style={{ padding: 32, textAlign: 'center' }}>
      <Spin description={label} />
    </div>
  );
}

export function EmptyState({
  title = 'Nothing here yet',
  description,
  action,
}: {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <Empty
      className="hp-empty"
      image={Empty.PRESENTED_IMAGE_SIMPLE}
      description={
        <span>
          <strong>{title}</strong>
          {description ? (
            <>
              <br />
              {description}
            </>
          ) : null}
        </span>
      }
    >
      {action}
    </Empty>
  );
}

export function PermissionDenied({ detail }: { detail?: ReactNode }) {
  return (
    <Result
      status="403"
      title="You don't have access"
      subTitle={detail ?? 'Your role does not include the permission required for this view.'}
    />
  );
}

/** Error view. 403 becomes the permission-denied state; network failures say so explicitly. */
export function ErrorState({
  error,
  onRetry,
  title,
}: {
  error: unknown;
  onRetry?: () => void;
  title?: ReactNode;
}) {
  if (isApiError(error) && error.isForbidden) {
    return <PermissionDenied detail={error.detail} />;
  }
  const heading =
    title ??
    (isApiError(error) && error.code === 'network_error' ? 'Server unreachable' : 'Could not load data');
  return (
    <Alert
      type="error"
      showIcon
      title={heading}
      description={errorMessage(error)}
      action={
        onRetry ? (
          <Button size="small" onClick={onRetry}>
            Retry
          </Button>
        ) : undefined
      }
    />
  );
}

/** Honest placeholder for pages whose work package has not landed yet. Never shows mock data. */
export function NotImplemented({ feature, workPackage }: { feature: string; workPackage?: string }) {
  return (
    <EmptyState
      title={`${feature} is not implemented yet`}
      description={
        workPackage
          ? `This page arrives with ${workPackage}. No data is shown until it is backed by the real API.`
          : 'No data is shown until this page is backed by the real API.'
      }
    />
  );
}
