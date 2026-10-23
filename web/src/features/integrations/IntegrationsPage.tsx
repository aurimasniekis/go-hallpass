import { EditOutlined, PlusOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import {
  Alert,
  Button,
  Card,
  Checkbox,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Tabs,
  type TableColumnsType,
} from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import {
  deliveriesQueryOptions,
  integrationsQueryOptions,
  notificationRoutesQueryOptions,
  type DeliveryState,
} from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { Delivery, Integration, NotificationRoute } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { CopyField } from '../../ds/CopyField';
import { DataTable } from '../../ds/DataTable';
import { PageHeader } from '../../ds/PageHeader';
import { EmptyState, ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { StatusBadge, type StatusTone } from '../../ds/StatusBadge';
import { revealControls } from '../../ds/untrusted';
import { formatDateTime, shortId } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { useSseState } from '../../stores/sse';
import {
  emptySelectorForm,
  formToSelector,
  isSelectorEmpty,
  summarizeSelector,
} from '../policy/selectors/model';
import { SelectorEditor } from '../policy/selectors/SelectorEditor';
import { IntegrationDrawer } from './IntegrationDrawer';
import { webhookUrl } from './integrationForm';

const PROVIDER_LABEL: Record<string, string> = { slack: 'Slack', telegram: 'Telegram' };

function EnabledBadge({ enabled }: { enabled: boolean }) {
  return <StatusBadge tone={enabled ? 'success' : 'neutral'}>{enabled ? 'Enabled' : 'Disabled'}</StatusBadge>;
}

function IntegrationCard({ integration, onEdit }: { integration: Integration; onEdit: () => void }) {
  const queryClient = useQueryClient();
  const url = webhookUrl(window.location.origin, integration.webhook_path);
  return (
    <Card
      size="small"
      title={
        <span>
          {integration.name} <span style={{ fontWeight: 400 }}>· {PROVIDER_LABEL[integration.provider]}</span>
        </span>
      }
      extra={
        <Space size={4}>
          <EnabledBadge enabled={integration.enabled} />
          <Button size="small" icon={<EditOutlined />} onClick={onEdit}>
            Edit
          </Button>
          <ConfirmAction
            label="Delete"
            title={`Delete integration “${integration.name}”?`}
            description="Its routes stop delivering and pending chat buttons stop working. Requests stay pending and can still be decided in the web console."
            typedConfirmation={integration.name}
            confirmLabel="Delete integration"
            buttonProps={{ size: 'small' }}
            onConfirm={() =>
              api.call('delete', '/api/v1/integrations/{id}', { path: { id: integration.id } })
            }
            onSuccess={() => {
              void queryClient.invalidateQueries({ queryKey: qk.integrations });
              void queryClient.invalidateQueries({ queryKey: qk.notificationRoutes });
            }}
          />
        </Space>
      }
    >
      <Space orientation="vertical" size={8} style={{ width: '100%' }}>
        <CopyField label="Webhook URL" value={url} />
        <span>
          {integration.provider === 'slack'
            ? 'Use this URL as the Interactivity Request URL and the slash-command URL of the Slack app.'
            : 'Hallpass registers this URL with Telegram (setWebhook) when an enabled integration is saved.'}{' '}
          Stored secrets:{' '}
          {integration.secrets_set.length ? integration.secrets_set.join(', ') : <strong>none</strong>}.
        </span>
      </Space>
    </Card>
  );
}

function IntegrationsTab() {
  const integrations = useQuery(integrationsQueryOptions());
  const [editing, setEditing] = useState<{ integration: Integration | undefined } | null>(null);
  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <div>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            setEditing({ integration: undefined });
          }}
        >
          New integration
        </Button>
      </div>
      {integrations.isPending ? (
        <LoadingState />
      ) : integrations.isError ? (
        <ErrorState error={integrations.error} onRetry={() => void integrations.refetch()} />
      ) : integrations.data.items.length === 0 ? (
        <EmptyState
          title="No chat integrations"
          description="Approvers can still decide every request in the web console. Add Slack or Telegram to notify approvers in chat."
        />
      ) : (
        integrations.data.items.map((i) => (
          <IntegrationCard
            key={i.id}
            integration={i}
            onEdit={() => {
              setEditing({ integration: i });
            }}
          />
        ))
      )}
      <IntegrationDrawer
        open={editing !== null}
        integration={editing?.integration}
        onClose={() => {
          setEditing(null);
        }}
      />
    </Space>
  );
}

interface RouteFormValues {
  integration_id: string;
  destination: string;
  enabled: boolean;
}

function NewRouteModal({
  open,
  integrations,
  onClose,
}: {
  open: boolean;
  integrations: readonly Integration[];
  onClose: () => void;
}) {
  const [form] = Form.useForm<RouteFormValues>();
  const [targets, setTargets] = useState(emptySelectorForm);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const queryClient = useQueryClient();
  const integrationId = Form.useWatch('integration_id', form);
  const provider = integrations.find((i) => i.id === integrationId)?.provider;

  const reset = () => {
    form.resetFields();
    setTargets(emptySelectorForm());
    setError(null);
    setProblems([]);
  };

  const submit = async (values: RouteFormValues) => {
    const built = formToSelector('target', targets);
    const errs = [...built.errors];
    if (isSelectorEmpty('target', targets)) {
      errs.push('The server selector is empty and would match nothing.');
    }
    setProblems(errs);
    setError(null);
    if (errs.length) {
      return;
    }
    setPending(true);
    try {
      await api.call('post', '/api/v1/notification-routes', {
        body: {
          integration_id: values.integration_id,
          destination: values.destination.trim(),
          targets: built.selector,
          enabled: values.enabled,
        },
      });
      await queryClient.invalidateQueries({ queryKey: qk.notificationRoutes });
      reset();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setPending(false);
    }
  };

  return (
    <Modal
      open={open}
      title="New notification route"
      width={720}
      destroyOnHidden
      onCancel={() => {
        if (!pending) {
          reset();
          onClose();
        }
      }}
      footer={null}
    >
      <Form<RouteFormValues>
        form={form}
        layout="vertical"
        requiredMark={false}
        initialValues={{ enabled: true }}
        onFinish={(v) => void submit(v)}
        aria-label="Notification route"
      >
        <Form.Item
          label="Integration"
          name="integration_id"
          rules={[{ required: true, message: 'Choose an integration' }]}
        >
          <Select
            options={integrations.map((i) => ({
              value: i.id,
              label: `${i.name} (${PROVIDER_LABEL[i.provider] ?? i.provider})`,
            }))}
          />
        </Form.Item>
        <Form.Item
          label={
            provider === 'telegram'
              ? 'Telegram chat ID'
              : provider === 'slack'
                ? 'Slack channel ID'
                : 'Destination'
          }
          name="destination"
          extra={
            provider === 'telegram'
              ? 'Group chat ID (negative, e.g. -1001234567890). The bot must be a member.'
              : 'Channel ID (e.g. C0123ABCD), not the channel name. Invite the app to the channel.'
          }
          rules={[{ required: true, message: 'Enter the destination' }]}
        >
          <Input spellCheck={false} />
        </Form.Item>
        <SelectorEditor
          kind="target"
          legend="Requests for these servers"
          value={targets}
          onChange={setTargets}
        />
        <Form.Item name="enabled" valuePropName="checked">
          <Checkbox>Enabled</Checkbox>
        </Form.Item>
        {problems.length || error !== null ? (
          <Alert
            type="error"
            showIcon
            role="alert"
            style={{ marginBottom: 12 }}
            title={error !== null ? errorMessage(error) : problems.join(' ')}
          />
        ) : null}
        <Space style={{ justifyContent: 'flex-end', width: '100%' }}>
          <Button
            onClick={() => {
              reset();
              onClose();
            }}
            disabled={pending}
          >
            Cancel
          </Button>
          <Button type="primary" htmlType="submit" loading={pending}>
            Create route
          </Button>
        </Space>
      </Form>
    </Modal>
  );
}

function RoutesTab() {
  const routes = useQuery(notificationRoutesQueryOptions());
  const integrations = useQuery(integrationsQueryOptions());
  const queryClient = useQueryClient();
  const sse = useSseState();
  const [creating, setCreating] = useState(false);
  const integrationName = (id: string) =>
    integrations.data?.items.find((i) => i.id === id)?.name ?? shortId(id);

  const cols: TableColumnsType<NotificationRoute> = [
    { key: 'integration', title: 'Integration', render: (_v, r) => integrationName(r.integration_id) },
    { key: 'provider', title: 'Provider', render: (_v, r) => PROVIDER_LABEL[r.provider] ?? r.provider },
    {
      key: 'destination',
      title: 'Destination',
      render: (_v, r) => <code className="hp-mono">{r.destination}</code>,
    },
    { key: 'targets', title: 'Servers', render: (_v, r) => summarizeSelector('target', r.targets) },
    { key: 'enabled', title: 'State', render: (_v, r) => <EnabledBadge enabled={r.enabled} /> },
    { key: 'created', title: 'Created', render: (_v, r) => formatDateTime(r.created_at) },
    {
      key: 'actions',
      title: <span className="hp-visually-hidden">Actions</span>,
      render: (_v, r) => (
        <ConfirmAction
          label="Delete"
          title="Delete this route?"
          description={`Requests will no longer be posted to ${r.destination}.`}
          confirmLabel="Delete route"
          buttonProps={{ size: 'small' }}
          onConfirm={() => api.call('delete', '/api/v1/notification-routes/{id}', { path: { id: r.id } })}
          onSuccess={() => {
            void queryClient.invalidateQueries({ queryKey: qk.notificationRoutes });
          }}
        />
      ),
    },
  ];

  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <p style={{ margin: 0 }}>
        Each pending request is posted once to every enabled route whose server selector matches. An empty
        selector matches nothing.
      </p>
      <div>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          disabled={!integrations.data?.items.length}
          onClick={() => {
            setCreating(true);
          }}
        >
          New route
        </Button>
      </div>
      <DataTable<NotificationRoute>
        caption="Notification routes"
        columns={cols}
        rows={routes.data?.items}
        rowKey="id"
        loading={routes.isPending}
        fetching={routes.isFetching}
        error={routes.error}
        onRetry={() => void routes.refetch()}
        stale={sse.status === 'stale' || sse.status === 'disconnected'}
        emptyTitle="No routes"
        emptyDescription="Create an integration first, then route requests to channels or chats."
      />
      <NewRouteModal
        open={creating}
        integrations={integrations.data?.items ?? []}
        onClose={() => {
          setCreating(false);
        }}
      />
    </Space>
  );
}

const DELIVERY_TONE: Record<string, [StatusTone, string]> = {
  queued: ['neutral', 'Queued'],
  sending: ['processing', 'Sending'],
  delivered: ['success', 'Delivered'],
  dead: ['error', 'Dead letter'],
};

export function DeliveryStateBadge({ state }: { state: string }) {
  const [tone, label] = DELIVERY_TONE[state] ?? ['neutral', state];
  return <StatusBadge tone={tone}>{label}</StatusBadge>;
}

function DeliveriesTab() {
  const [state, setState] = useState<DeliveryState | undefined>(undefined);
  const deliveries = useQuery(deliveriesQueryOptions(state));
  const sse = useSseState();
  const dead = deliveries.data?.items.filter((d) => d.state === 'dead').length ?? 0;

  const cols: TableColumnsType<Delivery> = [
    { key: 'created', title: 'Created', render: (_v, d) => formatDateTime(d.created_at) },
    { key: 'state', title: 'State', render: (_v, d) => <DeliveryStateBadge state={d.state} /> },
    { key: 'provider', title: 'Provider', render: (_v, d) => PROVIDER_LABEL[d.provider] ?? d.provider },
    {
      key: 'destination',
      title: 'Destination',
      render: (_v, d) => (d.destination ? <code className="hp-mono">{d.destination}</code> : '—'),
    },
    { key: 'kind', title: 'Kind', dataIndex: 'kind' },
    {
      key: 'subject',
      title: 'Subject',
      render: (_v, d) =>
        d.subject_type === 'request' && d.subject_id ? (
          <Link to="/requests/$id" params={{ id: d.subject_id }}>
            Request {shortId(d.subject_id)}
          </Link>
        ) : d.subject_id ? (
          `${d.subject_type ?? ''} ${shortId(d.subject_id)}`
        ) : (
          '—'
        ),
    },
    {
      key: 'attempts',
      title: 'Attempts',
      render: (_v, d) => `${String(d.attempts)} / ${String(d.max_attempts)}`,
    },
    {
      key: 'next',
      title: 'Next attempt',
      render: (_v, d) =>
        d.next_at && d.state !== 'delivered' && d.state !== 'dead' ? formatDateTime(d.next_at) : '—',
    },
    {
      key: 'error',
      title: 'Last error',
      render: (_v, d) =>
        d.last_error ? (
          <span style={{ wordBreak: 'break-word', maxWidth: 360, display: 'inline-block' }}>
            {revealControls(d.last_error)}
          </span>
        ) : (
          '—'
        ),
    },
  ];

  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      <Space wrap>
        <Select<DeliveryState | 'all'>
          aria-label="Delivery state"
          value={state ?? 'all'}
          style={{ width: 180 }}
          onChange={(v) => {
            setState(v === 'all' ? undefined : v);
          }}
          options={[
            { value: 'all', label: 'All states' },
            { value: 'queued', label: 'Queued' },
            { value: 'sending', label: 'Sending' },
            { value: 'delivered', label: 'Delivered' },
            { value: 'dead', label: 'Dead letters' },
          ]}
        />
      </Space>
      {dead > 0 && state !== 'dead' ? (
        <Alert
          type="warning"
          showIcon
          title={`${String(dead)} notification${dead === 1 ? '' : 's'} failed permanently (dead letter).`}
          description="A failed notification never approves anything; the request stays pending until it is decided in the console, canceled or expires."
        />
      ) : null}
      <DataTable<Delivery>
        caption="Notification deliveries"
        columns={cols}
        rows={deliveries.data?.items}
        rowKey="id"
        loading={deliveries.isPending}
        fetching={deliveries.isFetching}
        error={deliveries.error}
        onRetry={() => void deliveries.refetch()}
        stale={sse.status === 'stale' || sse.status === 'disconnected'}
        emptyTitle="No deliveries"
        emptyDescription="Deliveries appear here when requests match a notification route. The newest 100 are shown."
      />
    </Space>
  );
}

/** Settings → Integrations: chat approvals (docs/operator/approvals.md, HP-NTF-*). */
export function IntegrationsPage() {
  const { can, loading } = usePermissions();
  if (loading) {
    return null;
  }
  if (!can('integrations.manage')) {
    return (
      <>
        <PageHeader title="Integrations" />
        <PermissionDenied />
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Integrations"
        description="Slack and Telegram approvals: integrations, notification routes and the delivery outbox."
      />
      <Tabs
        items={[
          { key: 'integrations', label: 'Integrations', children: <IntegrationsTab /> },
          { key: 'routes', label: 'Routes', children: <RoutesTab /> },
          { key: 'deliveries', label: 'Deliveries', children: <DeliveriesTab /> },
        ]}
      />
    </>
  );
}
