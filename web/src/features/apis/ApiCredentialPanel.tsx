import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Form, Input, Select, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { ApiError } from '../../api/errors';
import { apiCredentialQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import type { APICredentialInput } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { KeyValueGrid } from '../../ds/KeyValueGrid';
import { ErrorState, LoadingState } from '../../ds/states';
import { formatDateTime } from '../../lib/format';
import { FormModal } from '../servers/FormModal';
import type { CredentialType } from './presets';

const TYPE_LABELS: Record<CredentialType, string> = {
  bearer: 'Bearer token',
  header: 'Custom header',
  basic: 'Basic (username and password)',
  google_service_account: 'Google service account key',
};

interface CredentialFormValues {
  type: CredentialType;
  header?: string;
  username?: string;
  scopes?: string;
  secret: string;
}

function CredentialFields() {
  const type = Form.useWatch<CredentialType | undefined>('type');
  return (
    <>
      <Form.Item label="Type" name="type">
        <Select
          aria-label="Credential type"
          options={(Object.keys(TYPE_LABELS) as CredentialType[]).map((t) => ({
            value: t,
            label: TYPE_LABELS[t],
          }))}
        />
      </Form.Item>
      {type === 'header' ? (
        <Form.Item
          label="Header"
          name="header"
          rules={[{ required: true, message: 'Enter the header name' }]}
        >
          <Input placeholder="X-Api-Key" spellCheck={false} />
        </Form.Item>
      ) : null}
      {type === 'basic' ? (
        <Form.Item
          label="Username"
          name="username"
          rules={[{ required: true, message: 'Enter the username' }]}
        >
          <Input spellCheck={false} />
        </Form.Item>
      ) : null}
      {type === 'google_service_account' ? (
        <>
          <Form.Item
            label="Service account key (JSON)"
            name="secret"
            rules={[{ required: true, message: 'Paste the key file' }]}
          >
            <Input.TextArea rows={6} spellCheck={false} className="hp-mono" autoComplete="off" />
          </Form.Item>
          <Form.Item
            label="Scopes"
            name="scopes"
            extra="One per line. Default: https://www.googleapis.com/auth/cloud-platform"
          >
            <Input.TextArea rows={2} spellCheck={false} className="hp-mono" />
          </Form.Item>
        </>
      ) : (
        <Form.Item
          label={type === 'basic' ? 'Password' : 'Token'}
          name="secret"
          rules={[{ required: true, message: 'Enter the secret' }]}
        >
          <Input.Password autoComplete="off" spellCheck={false} />
        </Form.Item>
      )}
    </>
  );
}

function toInput(v: CredentialFormValues): APICredentialInput {
  const body: APICredentialInput = { type: v.type, secret: v.secret };
  if (v.type === 'header') {
    body.header = (v.header ?? '').trim();
  }
  if (v.type === 'basic') {
    body.username = (v.username ?? '').trim();
  }
  if (v.type === 'google_service_account') {
    const scopes = (v.scopes ?? '')
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s !== '');
    if (scopes.length > 0) {
      body.scopes = scopes;
    }
  }
  return body;
}

/** The credential HallPass adds to an access profile's requests. The secret is write-only. */
export function ApiCredentialPanel({
  roleId,
  canWrite,
  defaultType,
  hint,
}: {
  roleId: string;
  canWrite: boolean;
  defaultType: CredentialType;
  hint: string;
}) {
  const queryClient = useQueryClient();
  const query = useQuery(apiCredentialQueryOptions(roleId));
  const [editing, setEditing] = useState(false);
  const missing = query.error instanceof ApiError && query.error.status === 404;

  if (query.isPending) {
    return <LoadingState />;
  }
  if (query.isError && !missing) {
    return <ErrorState error={query.error} onRetry={() => void query.refetch()} />;
  }
  const cred = query.data;
  return (
    <Space orientation="vertical" size={12} style={{ width: '100%' }}>
      {cred ? (
        <KeyValueGrid
          items={[
            { key: 'type', label: 'Credential', value: TYPE_LABELS[cred.type] },
            ...(cred.header
              ? [{ key: 'header', label: 'Header', value: <code className="hp-mono">{cred.header}</code> }]
              : []),
            ...(cred.username ? [{ key: 'user', label: 'Username', value: cred.username }] : []),
            { key: 'hint', label: 'Secret', value: cred.hint || 'set' },
            { key: 'version', label: 'Version', value: cred.version },
            { key: 'updated', label: 'Updated', value: formatDateTime(cred.updated_at) },
          ]}
        />
      ) : (
        <Alert
          type="warning"
          showIcon
          title="No credential"
          description={`Requests through this profile fail until a credential is set. ${hint}`}
        />
      )}
      {canWrite ? (
        <Space wrap>
          <Button
            onClick={() => {
              setEditing(true);
            }}
          >
            {cred ? 'Replace credential' : 'Set credential'}
          </Button>
          {cred ? (
            <ConfirmAction
              label="Remove credential"
              title="Remove this credential?"
              description="Requests through this profile fail until a new credential is set."
              confirmLabel="Remove"
              onConfirm={() =>
                api.call('delete', '/api/v1/roles/{id}/api-credential', { path: { id: roleId } })
              }
              onSuccess={() => {
                queryClient.removeQueries({ queryKey: qk.apiCredential(roleId) });
                void queryClient.invalidateQueries({ queryKey: qk.apiCredential(roleId) });
              }}
            />
          ) : null}
        </Space>
      ) : null}
      <FormModal<CredentialFormValues>
        open={editing}
        title={cred ? 'Replace credential' : 'Set credential'}
        okText="Save credential"
        formLabel="API credential"
        width={600}
        initialValues={{ type: cred?.type ?? defaultType, header: cred?.header, username: cred?.username }}
        onCancel={() => {
          setEditing(false);
        }}
        onSubmit={async (values) => {
          await api.call('put', '/api/v1/roles/{id}/api-credential', {
            path: { id: roleId },
            body: toInput(values),
          });
          await queryClient.invalidateQueries({ queryKey: qk.apiCredential(roleId) });
          setEditing(false);
        }}
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          title={hint}
          description="The secret is encrypted and never shown again."
        />
        <CredentialFields />
      </FormModal>
    </Space>
  );
}
