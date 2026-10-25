import { CloudUploadOutlined, SettingOutlined } from '@ant-design/icons';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Alert,
  App,
  Button,
  Card,
  Collapse,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Switch,
  Tooltip,
} from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import {
  backupRunsQueryOptions,
  backupStatusQueryOptions,
  backupTargetQueryOptions,
} from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { BackupRun, BackupTarget, BackupTargetInput } from '../../api/types';
import { CodeBlock } from '../../ds/CodeBlock';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { DataTable } from '../../ds/DataTable';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { PageHeader } from '../../ds/PageHeader';
import { ErrorState, LoadingState, PermissionDenied } from '../../ds/states';
import { StatusBadge } from '../../ds/StatusBadge';
import { formatBytes, formatDateTime, formatDuration } from '../../lib/format';
import { usePermissions } from '../../lib/usePermissions';
import { FormModal } from '../servers/FormModal';

const INTERVALS = ['15m', '30m', '1h', '3h', '6h', '12h', '24h'].map((v) => ({
  value: v,
  label: `Every ${v}`,
}));

/** Go duration strings from the API ("1h0m0s") back to the form's short form ("1h"). */
function shortInterval(d: string): string {
  return d.replace(/(\d+h)0m0s$/, '$1').replace(/^(\d+m)0s$/, '$1');
}

interface TargetFormValues {
  enabled: boolean;
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  path_style: boolean;
  access_key_id: string;
  secret_access_key?: string;
  interval: string;
  keep_last: number;
  keep_daily_days: number;
  allow_private_network: boolean;
  ca_bundle_pem?: string;
}

function RunState({ run }: { run: BackupRun }) {
  switch (run.state) {
    case 'succeeded':
      return run.error ? (
        <StatusBadge tone="warning">Succeeded with problems</StatusBadge>
      ) : (
        <StatusBadge tone="success">Succeeded</StatusBadge>
      );
    case 'running':
      return <StatusBadge tone="info">Running</StatusBadge>;
    case 'interrupted':
      return <StatusBadge tone="warning">Interrupted</StatusBadge>;
    default:
      return <StatusBadge tone="error">Failed</StatusBadge>;
  }
}

function runDuration(run: BackupRun): string {
  if (!run.finished_at) {
    return '—';
  }
  return formatDuration((new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()) / 1000);
}

function TargetForm({ editing }: { editing: boolean }) {
  return (
    <>
      <Form.Item name="enabled" label="Scheduled backups" valuePropName="checked">
        <Switch aria-label="Scheduled backups" />
      </Form.Item>
      <Form.Item
        name="endpoint"
        label="Endpoint"
        extra="For example https://s3.eu-central-1.amazonaws.com or https://<account>.r2.cloudflarestorage.com."
        rules={[{ required: true, whitespace: true }]}
      >
        <Input autoComplete="off" spellCheck={false} />
      </Form.Item>
      <Form.Item name="region" label="Region" extra="auto for Cloudflare R2." rules={[{ required: true }]}>
        <Input autoComplete="off" spellCheck={false} />
      </Form.Item>
      <Form.Item name="bucket" label="Bucket" rules={[{ required: true, whitespace: true }]}>
        <Input autoComplete="off" spellCheck={false} />
      </Form.Item>
      <Form.Item name="prefix" label="Prefix" extra="Optional, for example hallpass/ (ends with a slash).">
        <Input autoComplete="off" spellCheck={false} />
      </Form.Item>
      <Form.Item name="access_key_id" label="Access key ID" rules={[{ required: true, whitespace: true }]}>
        <Input autoComplete="off" spellCheck={false} />
      </Form.Item>
      <Form.Item
        name="secret_access_key"
        label="Secret access key"
        extra={editing ? 'Leave empty to keep the stored key.' : 'Stored encrypted and never shown again.'}
        rules={editing ? [] : [{ required: true }]}
      >
        <Input.Password autoComplete="new-password" />
      </Form.Item>
      <Form.Item name="interval" label="Schedule">
        <Select options={INTERVALS} />
      </Form.Item>
      <Form.Item name="keep_last" label="Keep the newest" extra="Successful backups, at least 1.">
        <InputNumber min={1} max={1000} precision={0} />
      </Form.Item>
      <Form.Item
        name="keep_daily_days"
        label="And one per day for (days)"
        extra="Also keeps the newest backup of each of these past days. 0 keeps only the newest."
      >
        <InputNumber min={0} max={3650} precision={0} />
      </Form.Item>
      <Collapse
        ghost
        items={[
          {
            key: 'advanced',
            label: 'Advanced',
            children: (
              <>
                <Form.Item
                  name="path_style"
                  label="Path-style addressing"
                  valuePropName="checked"
                  extra="Address the bucket as endpoint/bucket. Needed for MinIO and some other servers."
                >
                  <Switch aria-label="Path-style addressing" />
                </Form.Item>
                <Form.Item
                  name="allow_private_network"
                  label="Allow a private network"
                  valuePropName="checked"
                  extra="Let the endpoint resolve to a private, loopback or link-local address, such as a MinIO on your network."
                >
                  <Switch aria-label="Allow a private network" />
                </Form.Item>
                <Form.Item
                  name="ca_bundle_pem"
                  label="Extra CA certificates (PEM)"
                  extra="For an endpoint with a private CA."
                >
                  <Input.TextArea rows={4} spellCheck={false} />
                </Form.Item>
              </>
            ),
          },
        ]}
      />
    </>
  );
}

function initialValues(t: BackupTarget | null): Partial<TargetFormValues> {
  if (!t) {
    return {
      enabled: true,
      region: 'us-east-1',
      prefix: 'hallpass/',
      interval: '1h',
      keep_last: 48,
      keep_daily_days: 30,
      path_style: false,
      allow_private_network: false,
    };
  }
  return {
    enabled: t.enabled,
    endpoint: t.endpoint,
    region: t.region,
    bucket: t.bucket,
    prefix: t.prefix,
    path_style: t.path_style,
    access_key_id: t.access_key_id,
    interval: shortInterval(t.interval),
    keep_last: t.keep_last,
    keep_daily_days: t.keep_daily_days,
    allow_private_network: t.allow_private_network,
    ca_bundle_pem: t.ca_bundle_pem ?? '',
  };
}

/**
 * Settings → Backups: scheduled backups to S3-compatible object storage (ADR-0054). Each backup is a sealed database
 * snapshot plus the recording files it references; only ciphertext reaches the bucket, and restoring needs the KEK.
 */
export function BackupsPage() {
  const { can, loading } = usePermissions();
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const [editing, setEditing] = useState(false);
  const [testing, setTesting] = useState(false);
  const readable = can('system.read');
  const writable = can('system.settings');
  const status = useQuery({ ...backupStatusQueryOptions(), enabled: readable, refetchInterval: 15_000 });
  const target = useQuery({ ...backupTargetQueryOptions(), enabled: readable });
  const runs = useQuery({
    ...backupRunsQueryOptions(),
    enabled: readable,
    refetchInterval: status.data?.running ? 3_000 : 30_000,
  });
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: qk.backups });
  };

  if (loading) {
    return <LoadingState />;
  }
  if (!readable) {
    return (
      <>
        <PageHeader title="Backups" />
        <PermissionDenied />
      </>
    );
  }
  const tg = target.data ?? null;
  const st = status.data;

  const testConnection = async () => {
    setTesting(true);
    try {
      const res = await api.call('post', '/api/v1/system/backups/target/test');
      if (res.ok) {
        void message.success(`Connected. ${String(res.backups)} backup(s) found below the prefix.`);
      } else {
        void message.error(`Connection test failed: ${res.error ?? 'unknown error'}`);
      }
    } catch (e) {
      void message.error(errorMessage(e));
    } finally {
      setTesting(false);
    }
  };

  const backupNow = async () => {
    try {
      await api.call('post', '/api/v1/system/backups/runs', {});
      void message.success('Backup started');
      refresh();
    } catch (e) {
      void message.error(errorMessage(e));
    }
  };

  return (
    <>
      <PageHeader
        title="Backups"
        description="Scheduled, encrypted backups to S3-compatible object storage (AWS S3, Cloudflare R2, MinIO and others)."
        extra={
          writable && tg ? (
            <Space>
              <Button
                type="primary"
                icon={<CloudUploadOutlined />}
                disabled={st?.running}
                onClick={() => void backupNow()}
              >
                Back up now
              </Button>
              <Button
                icon={<SettingOutlined />}
                onClick={() => {
                  setEditing(true);
                }}
              >
                Edit target
              </Button>
            </Space>
          ) : null
        }
      />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Alert
          type="info"
          showIcon
          title="The master key (KEK) is not in any backup"
          description="Backups are encrypted before they leave this server, and restoring one needs the KEK. Keep the KEK backed up offline, separately from the bucket: without it no backup can be restored."
        />
        {target.isPending ? (
          <LoadingState />
        ) : target.isError ? (
          <ErrorState error={target.error} onRetry={() => void target.refetch()} />
        ) : !tg ? (
          <Card size="small" title="Not set up">
            <Space orientation="vertical" size={12}>
              <p style={{ margin: 0 }}>
                Point HallPass at a bucket and it backs up the database and recordings on a schedule. Use a
                bucket and an access key for HallPass alone, with permission to list, read, write and delete
                objects below the prefix.
              </p>
              {writable ? (
                <Button
                  type="primary"
                  onClick={() => {
                    setEditing(true);
                  }}
                >
                  Set up backups
                </Button>
              ) : null}
            </Space>
          </Card>
        ) : (
          <Card
            size="small"
            title="Target"
            extra={
              writable ? (
                <Space>
                  <Button size="small" loading={testing} onClick={() => void testConnection()}>
                    Test connection
                  </Button>
                  <ConfirmAction<undefined>
                    label="Stop backups"
                    title="Stop remote backups?"
                    confirmLabel="Stop backups"
                    danger
                    buttonProps={{ size: 'small' }}
                    description="The target settings and key are deleted. Backups already in the bucket stay there; delete them in the bucket if you no longer need them."
                    onConfirm={async () => {
                      await api.call('delete', '/api/v1/system/backups/target');
                      return undefined;
                    }}
                    onSuccess={() => {
                      void message.success('Remote backups stopped');
                      refresh();
                    }}
                  />
                </Space>
              ) : null
            }
          >
            <KeyValueGrid
              items={[
                {
                  key: 'state',
                  label: 'Schedule',
                  value: tg.enabled ? (
                    <StatusBadge tone="success">Every {shortInterval(tg.interval)}</StatusBadge>
                  ) : (
                    <StatusBadge tone="neutral">Paused</StatusBadge>
                  ),
                },
                {
                  key: 'where',
                  label: 'Bucket',
                  value: (
                    <code className="hp-mono">
                      {tg.bucket}/{tg.prefix}
                    </code>
                  ),
                },
                { key: 'endpoint', label: 'Endpoint', value: <code className="hp-mono">{tg.endpoint}</code> },
                {
                  key: 'retention',
                  label: 'Keeps',
                  value:
                    tg.keep_daily_days > 0
                      ? `The newest ${String(tg.keep_last)}, plus one per day for ${String(tg.keep_daily_days)} days`
                      : `The newest ${String(tg.keep_last)}`,
                },
                {
                  key: 'last',
                  label: 'Last success',
                  value: st?.last_success
                    ? `${formatDateTime(st.last_success.started_at)} (${formatBytes(st.last_success.db_bytes)} database)`
                    : 'None yet',
                },
                {
                  key: 'next',
                  label: 'Next backup',
                  value: st?.running ? (
                    <StatusBadge tone="info">Running now</StatusBadge>
                  ) : st?.next_run_at ? (
                    formatDateTime(st.next_run_at)
                  ) : (
                    '—'
                  ),
                },
              ]}
            />
          </Card>
        )}
        <DataTable<BackupRun>
          caption="Backup runs"
          rowKey="id"
          rows={runs.data}
          loading={runs.isPending}
          fetching={runs.isFetching}
          error={runs.error}
          onRetry={() => void runs.refetch()}
          emptyTitle="No backups yet"
          emptyDescription="Runs appear here once the first backup starts."
          columns={[
            { key: 'started', title: 'Started', render: (_, r) => formatDateTime(r.started_at) },
            {
              key: 'trigger',
              title: 'Trigger',
              render: (_, r) => (r.trigger === 'manual' ? 'Manual' : 'Schedule'),
            },
            { key: 'state', title: 'Result', render: (_, r) => <RunState run={r} /> },
            { key: 'duration', title: 'Duration', render: (_, r) => runDuration(r) },
            {
              key: 'size',
              title: 'Uploaded',
              render: (_, r) => (r.uploaded_bytes === undefined ? '—' : formatBytes(r.uploaded_bytes)),
            },
            {
              key: 'segments',
              title: 'Recordings',
              render: (_, r) =>
                r.segments === undefined
                  ? '—'
                  : `${String(r.segments)} (${String(r.segments_uploaded ?? 0)} new)`,
            },
            {
              key: 'stored',
              title: 'In bucket',
              render: (_, r) =>
                r.state !== 'succeeded' ? (
                  '—'
                ) : r.stored ? (
                  'Yes'
                ) : (
                  <StatusBadge tone="neutral">Removed</StatusBadge>
                ),
            },
            {
              key: 'error',
              title: 'Details',
              render: (_, r) =>
                r.error ? (
                  <Tooltip title={r.error}>
                    <span className="hp-truncate" style={{ maxWidth: 320, display: 'inline-block' }}>
                      {r.error}
                    </span>
                  </Tooltip>
                ) : null,
            },
          ]}
        />
        <Card size="small" title="Restore on a new host">
          <p style={{ marginTop: 0 }}>
            Install HallPass and its KEK, then download a backup with the bucket details and an access key
            that may read it, verify it and restore it:
          </p>
          <CodeBlock
            code={[
              'export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…',
              `hallpass backup remote-list --s3-endpoint ${tg?.endpoint ?? 'https://…'} --s3-bucket ${tg?.bucket ?? '…'} --s3-prefix '${tg?.prefix ?? ''}'${tg?.region && tg.region !== 'us-east-1' ? ` --s3-region ${tg.region}` : ''}${tg?.path_style ? ' --s3-path-style' : ''}`,
              'hallpass backup remote-download --config /etc/hallpass/hallpass.yaml --out /var/tmp/hp-restore <same --s3-… flags>',
              'hallpass backup verify /var/tmp/hp-restore && hallpass restore --config /etc/hallpass/hallpass.yaml /var/tmp/hp-restore',
            ].join('\n')}
          />
        </Card>
      </Space>
      <FormModal<TargetFormValues>
        open={editing}
        title={tg ? 'Backup target' : 'Set up backups'}
        okText="Save"
        formLabel="Backup target"
        width={620}
        initialValues={initialValues(tg)}
        onCancel={() => {
          setEditing(false);
        }}
        onSubmit={async (values) => {
          const body: BackupTargetInput = { ...values };
          if (!body.secret_access_key) {
            delete body.secret_access_key;
          }
          await api.call('put', '/api/v1/system/backups/target', {
            body,
            ...(tg ? { ifMatch: tg.version } : {}),
          });
          setEditing(false);
          void message.success('Backup target saved');
          refresh();
        }}
      >
        <TargetForm editing={tg !== null} />
      </FormModal>
    </>
  );
}
