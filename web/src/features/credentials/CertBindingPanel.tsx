import { useQuery } from '@tanstack/react-query';
import { App, Button, Card, Form, Select, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { userCAsQueryOptions } from '../../api/queries';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { DurationInput } from '../../ds/DurationInput';
import { TagsInput } from '../../ds/TagsInput';
import { cleanList } from '../servers/formUtils';
import { FormModal } from '../servers/FormModal';

export interface CertBindingValues {
  user_ca_id: string;
  principals?: string[];
  /** seconds */
  ttl?: number | null;
}

export function toCertBinding(v: CertBindingValues): {
  user_ca_id: string;
  principals: string[];
  ttl?: number;
} {
  return {
    user_ca_id: v.user_ca_id,
    principals: cleanList(v.principals),
    ...(v.ttl ? { ttl: Math.round(v.ttl) } : {}),
  };
}

/**
 * Certificate login binding for a role (`PUT/DELETE /roles/{id}/cert-binding`). The API does not return
 * the current binding (Role has no binding fields), so this panel can set or remove it but not show it.
 */
export function CertBindingPanel({ roleId, remoteUser }: { roleId: string; remoteUser: string }) {
  const { message } = App.useApp();
  const cas = useQuery(userCAsQueryOptions());
  const [open, setOpen] = useState(false);
  return (
    <Card
      size="small"
      title="Certificate login"
      extra={
        <Space>
          <Button
            size="small"
            onClick={() => {
              setOpen(true);
            }}
          >
            Bind user CA
          </Button>
          <ConfirmAction
            label="Remove binding"
            title="Remove certificate binding"
            confirmLabel="Remove"
            buttonProps={{ size: 'small' }}
            description="Hallpass stops issuing certificates for this role. Connections then need an active login key."
            onConfirm={() => api.call('delete', '/api/v1/roles/{id}/cert-binding', { path: { id: roleId } })}
            onSuccess={() => void message.success('Certificate binding removed.')}
          />
        </Space>
      }
    >
      <p style={{ margin: 0 }}>
        Instead of a static key, Hallpass can sign a short-lived certificate per connection with a user CA.
        The current binding is not reported by the API; binding again replaces it.
      </p>
      <FormModal<CertBindingValues>
        open={open}
        title="Bind user CA"
        okText="Bind"
        formLabel="Bind user CA"
        initialValues={{ principals: remoteUser ? [remoteUser] : [] }}
        onCancel={() => {
          setOpen(false);
        }}
        onSubmit={async (v) => {
          await api.call('put', '/api/v1/roles/{id}/cert-binding', {
            path: { id: roleId },
            body: toCertBinding(v),
          });
          void message.success('Certificate binding saved.');
          setOpen(false);
        }}
      >
        <Form.Item label="User CA" name="user_ca_id" rules={[{ required: true, message: 'Choose a CA' }]}>
          <Select
            aria-label="User CA"
            loading={cas.isPending}
            options={(cas.data?.items ?? [])
              .filter((c) => c.state === 'active')
              .map((c) => ({ value: c.id, label: `${c.name} (${c.fingerprint})` }))}
          />
        </Form.Item>
        <Form.Item
          label="Principals"
          name="principals"
          rules={[{ required: true, message: 'Add at least one principal' }]}
          extra="Usually the remote user name accepted by the destination's AuthorizedPrincipals."
        >
          <TagsInput aria-label="Principals" />
        </Form.Item>
        <Form.Item
          label="Certificate lifetime"
          name="ttl"
          extra="Optional; the server default applies when unset."
        >
          <DurationInput aria-label="Certificate lifetime" minSeconds={60} />
        </Form.Item>
      </FormModal>
    </Card>
  );
}
