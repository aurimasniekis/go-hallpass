import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { Alert, Card, Input, Radio, Space } from 'antd';
import { useId, useState } from 'react';

import { api } from '../../api/client';
import { requestQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { AccessRequest, Decision } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { Countdown } from '../../ds/Countdown';
import { DurationInput } from '../../ds/DurationInput';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { UntrustedText } from '../../ds/UntrustedText';
import { formatDateTime, formatDuration, formatDurationLong } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { AgentName, RoleName, ServerName } from '../../shared/names';
import { StateBadge } from '../../shared/StateBadge';
import { approveBody, choiceKey, DURATION_PRESETS, parseChoiceKey, type DurationChoice } from './decision';

function useDecisionInvalidation(id: string) {
  const queryClient = useQueryClient();
  return () => {
    for (const key of [qk.requests, qk.request(id), qk.grants, qk.system, qk.accessSessions]) {
      void queryClient.invalidateQueries({ queryKey: key });
    }
  };
}

function CommentField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} style={{ display: 'block', marginBottom: 4 }}>
        Comment (optional, recorded in the audit log)
      </label>
      <Input.TextArea
        id={id}
        value={value}
        maxLength={1000}
        autoSize={{ minRows: 2, maxRows: 5 }}
        onChange={(e) => {
          onChange(e.target.value);
        }}
      />
    </div>
  );
}

function ApproveAction({ request, onDecided }: { request: AccessRequest; onDecided: (d: Decision) => void }) {
  const [choice, setChoice] = useState<DurationChoice>({ kind: 'requested' });
  const [custom, setCustom] = useState<number | null>(null);
  const [comment, setComment] = useState('');
  const groupId = useId();
  const body = approveBody(choice, custom, comment);
  return (
    <ConfirmAction<Decision>
      label="Approve"
      title="Approve access request"
      danger={false}
      confirmLabel="Approve"
      buttonProps={{ type: 'primary' }}
      confirmDisabled={body === null}
      onOpen={() => {
        setChoice({ kind: 'requested' });
        setCustom(null);
        setComment('');
      }}
      description={
        <Space orientation="vertical" size={12} style={{ width: '100%' }}>
          <p style={{ margin: 0 }}>
            The grant starts when the server records the decision. Policy and your approver scope may shorten
            the duration; the result below shows what the server granted.
          </p>
          <div role="group" aria-labelledby={groupId}>
            <div id={groupId} style={{ marginBottom: 4 }}>
              Grant duration
            </div>
            <Radio.Group
              value={choiceKey(choice)}
              onChange={(e) => {
                setChoice(parseChoiceKey(String(e.target.value)));
              }}
            >
              <Space orientation="vertical">
                <Radio value="requested">Requested ({formatDuration(request.requested_duration)})</Radio>
                {DURATION_PRESETS.map((s) => (
                  <Radio key={s} value={`preset:${String(s)}`}>
                    {formatDurationLong(s)}
                  </Radio>
                ))}
                <Radio value="custom">Custom</Radio>
              </Space>
            </Radio.Group>
          </div>
          {choice.kind === 'custom' ? (
            <DurationInput aria-label="Custom duration" value={custom} onChange={setCustom} minSeconds={60} />
          ) : null}
          <CommentField value={comment} onChange={setComment} />
        </Space>
      }
      onConfirm={({ idempotencyKey }) =>
        api.call('post', '/api/v1/requests/{id}/approve', {
          path: { id: request.id },
          body: body ?? { duration: 0 },
          idempotencyKey,
        })
      }
      onSuccess={onDecided}
    />
  );
}

function DenyAction({ request, onDecided }: { request: AccessRequest; onDecided: (d: Decision) => void }) {
  const [comment, setComment] = useState('');
  return (
    <ConfirmAction<Decision>
      label="Deny"
      title="Deny access request"
      confirmLabel="Deny"
      onOpen={() => {
        setComment('');
      }}
      description={<CommentField value={comment} onChange={setComment} />}
      onConfirm={({ idempotencyKey }) =>
        api.call('post', '/api/v1/requests/{id}/deny', {
          path: { id: request.id },
          body: comment.trim() === '' ? {} : { comment: comment.trim() },
          idempotencyKey,
        })
      }
      onSuccess={onDecided}
    />
  );
}

function DecisionResult({ decision }: { decision: Decision }) {
  const grant = decision.grant ?? null;
  if (decision.request.state === 'approved' && grant) {
    return (
      <Alert
        type="success"
        showIcon
        title="Approved by the server"
        description={
          <span>
            Grant for{' '}
            {formatDurationLong(
              Math.max(0, (Date.parse(grant.expires_at) - Date.parse(grant.starts_at)) / 1000),
            )}
            , until {formatDateTime(grant.expires_at)}.{' '}
            {grant.session_id ? (
              <Link to="/sessions/$id" params={{ id: grant.session_id }}>
                Open access session
              </Link>
            ) : null}
          </span>
        }
      />
    );
  }
  return (
    <Alert
      type={decision.request.state === 'denied' ? 'info' : 'warning'}
      showIcon
      title={`Server recorded: ${decision.request.state}`}
      description={decision.request.state_reason}
    />
  );
}

export function ReasonView({ request }: { request: AccessRequest }) {
  if (typeof request.reason === 'string') {
    return <UntrustedText text={request.reason} source="the agent" label="Agent reason (untrusted)" block />;
  }
  if (request.has_reason) {
    return <span>Provided, but hidden: viewing reasons needs the requests.reason.read permission.</span>;
  }
  return <span>No reason given</span>;
}

/** Request detail with decision actions (HP-UI-003, HP-UI-012: success shown only from the server). */
export function RequestDetailPage({ id }: { id: string }) {
  const { can, loading } = usePermissions();
  const q = useQuery({ ...requestQueryOptions(id), enabled: can('requests.read') });
  const invalidate = useDecisionInvalidation(id);
  const [decision, setDecision] = useState<Decision | null>(null);
  const onDecided = (d: Decision) => {
    setDecision(d);
    invalidate();
  };
  const back = <Link to="/requests">← Requests</Link>;

  if (loading) {
    return <LoadingState />;
  }
  if (!can('requests.read')) {
    return (
      <>
        <PageHeader title="Request" above={back} />
        <PermissionDenied />
      </>
    );
  }
  if (q.isPending) {
    return (
      <>
        <PageHeader title="Request" above={back} />
        <LoadingState />
      </>
    );
  }
  if (q.isError) {
    return (
      <>
        <PageHeader title="Request" above={back} />
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      </>
    );
  }
  const r = q.data;
  const pending = r.state === 'pending';
  const actions = pending ? (
    <Space wrap>
      {can('requests.decide') ? <ApproveAction request={r} onDecided={onDecided} /> : null}
      {can('requests.decide') ? <DenyAction request={r} onDecided={onDecided} /> : null}
      {can('requests.cancel') ? (
        <ConfirmAction<AccessRequest>
          label="Cancel request"
          title="Cancel this request"
          confirmLabel="Cancel request"
          description="The agent's request is withdrawn without a decision. The agent can request again."
          onConfirm={({ idempotencyKey }) =>
            api.call('post', '/api/v1/requests/{id}/cancel', { path: { id: r.id }, idempotencyKey })
          }
          onSuccess={() => {
            invalidate();
          }}
        />
      ) : null}
    </Space>
  ) : null;

  return (
    <>
      <PageHeader
        title="Request"
        above={back}
        description={<code className="hp-mono">{r.id}</code>}
        extra={actions}
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        {decision ? <DecisionResult decision={decision} /> : null}
        <Card title="Summary" size="small">
          <KeyValueGrid
            items={[
              { key: 'state', label: 'State', value: <StateBadge kind="request" state={r.state} /> },
              {
                key: 'expires',
                label: pending ? 'Expires in' : 'Expired at',
                value: pending ? <Countdown deadline={r.expires_at} /> : formatDateTime(r.expires_at),
              },
              { key: 'agent', label: 'Agent', value: <AgentName id={r.agent_id} /> },
              {
                key: 'key',
                label: 'Agent key',
                value: r.agent_key_id ? <code className="hp-mono">{r.agent_key_id}</code> : '—',
              },
              { key: 'server', label: 'Server', value: <ServerName id={r.server_id} /> },
              { key: 'role', label: 'Role', value: <RoleName id={r.role_id} /> },
              {
                key: 'duration',
                label: 'Requested duration',
                value: (
                  <span title={formatDurationLong(r.requested_duration)}>
                    {formatDuration(r.requested_duration)}
                  </span>
                ),
              },
              { key: 'policy', label: 'Policy version', value: r.policy_version },
              { key: 'created', label: 'Created', value: formatDateTime(r.created_at) },
              { key: 'decided', label: 'Decided', value: r.decided_at ? formatDateTime(r.decided_at) : '—' },
              {
                key: 'state_reason',
                label: 'State reason',
                value: r.state_reason ? <code className="hp-mono">{r.state_reason}</code> : '—',
              },
            ]}
          />
        </Card>
        <Card title="Reason" size="small">
          <ReasonView request={r} />
        </Card>
      </Space>
    </>
  );
}
