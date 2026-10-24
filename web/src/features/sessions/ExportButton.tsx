import { DownloadOutlined, UnlockOutlined } from '@ant-design/icons';
import { Space } from 'antd';

import { api } from '../../api/client';
import type { SessionExport } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { usePermissions } from '../../lib/usePermissions';

/** File name for an export; IDs are server-generated but sanitized anyway. */
export function exportFileName(sessionId: string, ext: 'json' | 'tar' = 'json'): string {
  return `hallpass-session-${sessionId.replace(/[^A-Za-z0-9_.-]/g, '_')}.${ext}`;
}

/** Offers a blob as a download without ever rendering its (untrusted) content. */
export function downloadBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = fileName;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 0);
}

/** Offers a JSON value as a download without ever rendering its (untrusted) content. */
export function downloadJson(data: unknown, fileName: string): void {
  downloadBlob(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }), fileName);
}

/**
 * Recording export (HP-REC-014): `GET /access-sessions/{id}/export` needs `recording.export` and recent
 * authentication with MFA (ReauthGate prompts). The default is the ciphertext bundle (a tar of the encrypted
 * segment files and a manifest). The decrypted JSON export is a separate, explicitly warned action. Files are
 * created in the browser and never displayed.
 */
export function ExportButton({ sessionId }: { sessionId: string }) {
  const { can } = usePermissions();
  if (!can('recording.export')) {
    return null;
  }
  const path = '/api/v1/access-sessions/{id}/export' as const;
  return (
    <Space wrap>
      <ConfirmAction<Blob>
        label="Export encrypted bundle"
        title="Export the encrypted recording bundle?"
        confirmLabel="Export"
        danger={false}
        buttonProps={{ icon: <DownloadOutlined /> }}
        description={
          <>
            <p>
              Downloads the recording files exactly as stored (encrypted) with a manifest of hashes. Reading
              them needs this gateway&apos;s keys.
            </p>
            <p>The export is recorded in the audit log. You may be asked to confirm your identity.</p>
          </>
        }
        onConfirm={() =>
          api.call('get', path, {
            path: { id: sessionId },
            query: { format: 'bundle' },
            responseType: 'blob',
          }) as unknown as Promise<Blob>
        }
        onSuccess={(blob) => {
          downloadBlob(blob, exportFileName(sessionId, 'tar'));
        }}
      />
      <ConfirmAction<SessionExport>
        label="Export decrypted"
        title="Export decrypted recordings?"
        confirmLabel="Export decrypted"
        buttonProps={{ icon: <UnlockOutlined /> }}
        description={
          <>
            <p>
              The file contains the <strong>decrypted</strong> terminal output (and input, if it was recorded)
              of every channel in this session. It may include secrets. HallPass does not redact it.
            </p>
            <p>The export is recorded in the audit log. You may be asked to confirm your identity.</p>
          </>
        }
        onConfirm={() =>
          api.call('get', path, {
            path: { id: sessionId },
            query: { format: 'plaintext' },
          })
        }
        onSuccess={(data) => {
          downloadJson(data, exportFileName(sessionId));
        }}
      />
    </Space>
  );
}
