import { Card, Space } from 'antd';

import { PageHeader } from '../../ds/PageHeader';
import { NotImplemented } from '../../ds/states';

/**
 * Settings → Storage & keys (PLAN §14.3). The backing endpoints (`GET /system/storage`, `GET /system/keys`,
 * `GET/PUT /system/retention`, `POST /system/backup`) are not in api/openapi.yaml yet (ADR-0031 defers
 * them to WP23), so this page shows no numbers rather than invented ones.
 */
export function StoragePage() {
  return (
    <>
      <PageHeader title="Storage & keys" description="Retention classes, storage usage and keyring status." />
      <Space orientation="vertical" size={16} style={{ width: '100%' }}>
        <Card size="small">
          <NotImplemented
            feature="Storage, retention and key status"
            workPackage="WP23 (needs GET /system/storage, GET /system/keys and GET/PUT /system/retention in the API)"
          />
        </Card>
        <Card size="small" title="Until then">
          <p style={{ margin: 0 }}>
            Use <code className="hp-mono">hallpass keys status</code>,{' '}
            <code className="hp-mono">hallpass verify</code> and the{' '}
            <code className="hp-mono">hallpass_storage_*</code> metrics on the server
            (docs/operator/storage.md, keys.md).
          </p>
        </Card>
      </Space>
    </>
  );
}
