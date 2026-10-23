import { DownloadOutlined } from '@ant-design/icons';

import { api } from '../../api/client';
import type { SessionExport } from '../../api/types';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { usePermissions } from '../../lib/usePermissions';

/** File name for an export; IDs are server-generated but sanitized anyway. */
export function exportFileName(sessionId: string): string {
  return `hallpass-session-${sessionId.replace(/[^A-Za-z0-9_.-]/g, '_')}.json`;
}

/** Offers a JSON blob as a download without ever rendering its (untrusted) content. */
export function downloadJson(data: unknown, fileName: string): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
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

/**
 * Recording export (HP-REC-014): `GET /access-sessions/{id}/export` needs `recording.export` and recent
 * authentication with MFA (ReauthGate prompts). The server returns DECRYPTED records; the file is
 * created in the browser and never displayed.
 */
export function ExportButton({ sessionId }: { sessionId: string }) {
  const { can } = usePermissions();
  if (!can('recording.export')) {
    return null;
  }
  return (
    <ConfirmAction<SessionExport>
      label="Export recordings"
      title="Export decrypted recordings?"
      confirmLabel="Export"
      danger={false}
      buttonProps={{ icon: <DownloadOutlined /> }}
      description={
        <>
          <p>
            The file contains the <strong>decrypted</strong> terminal output (and input, if it was recorded)
            of every channel in this session. It may include secrets. Hallpass does not redact it.
          </p>
          <p>The export is recorded in the audit log. You may be asked to confirm your identity.</p>
        </>
      }
      onConfirm={() => api.call('get', '/api/v1/access-sessions/{id}/export', { path: { id: sessionId } })}
      onSuccess={(data) => {
        downloadJson(data, exportFileName(sessionId));
      }}
    />
  );
}
