import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Space } from 'antd';
import { useState } from 'react';

import { api } from '../../api/client';
import { errorMessage } from '../../api/errors';
import { myProviderLinksQueryOptions } from '../../api/queries';
import { qk } from '../../api/queryKeys';
import { ConfirmAction } from '../../ds/ConfirmAction';
import { CopyField } from '../../ds/CopyField';
import { Countdown } from '../../ds/Countdown';
import { CHAT_PROVIDERS, chatProviderLabel, ProviderLinksTable } from '../operators/tables';
import { linkInstruction, type ChatProvider } from './chatLink';

interface IssuedCode {
  provider: ChatProvider;
  code: string;
  expires_at: string;
}

/**
 * Link a Slack or Telegram account so chat approvals are attributed to you (HP-NTF-011). The code is
 * single use, valid 10 minutes, and kept only in this component's memory until dismissed.
 */
export function ChatAccounts() {
  const links = useQuery(myProviderLinksQueryOptions());
  const queryClient = useQueryClient();
  const [issued, setIssued] = useState<IssuedCode | null>(null);
  const [pending, setPending] = useState<ChatProvider | null>(null);
  const [error, setError] = useState<unknown>(null);

  const createCode = async (provider: ChatProvider) => {
    setPending(provider);
    setError(null);
    try {
      const res = await api.call('post', '/api/v1/me/provider-link-codes', { body: { provider } });
      setIssued({ provider, code: res.code, expires_at: res.expires_at });
    } catch (e) {
      setError(e);
    } finally {
      setPending(null);
    }
  };

  const instruction = issued ? linkInstruction(issued.provider, issued.code) : null;

  return (
    <Space orientation="vertical" size={16} style={{ width: '100%' }}>
      <p style={{ margin: 0 }}>
        Approvals from Slack or Telegram are accepted only from linked accounts, and every decision still
        passes the same checks as in the web UI.
      </p>
      <ProviderLinksTable
        caption="My chat accounts"
        rows={links.data?.items}
        loading={links.isPending}
        error={links.error}
        onRetry={() => void links.refetch()}
        action={(l) => (
          <ConfirmAction
            label="Unlink"
            title={`Unlink ${chatProviderLabel(l.provider)} account`}
            description="Decisions from this chat account will no longer be accepted."
            confirmLabel="Unlink"
            buttonProps={{ size: 'small' }}
            onConfirm={() =>
              api.call('delete', '/api/v1/me/provider-links', {
                query: { provider: l.provider, workspace: l.workspace, user_id: l.provider_user_id },
              })
            }
            onSuccess={() => {
              void queryClient.invalidateQueries({ queryKey: qk.myProviderLinks });
            }}
          />
        )}
      />
      <Space wrap>
        {CHAT_PROVIDERS.map((p) => (
          <Button key={p.value} loading={pending === p.value} onClick={() => void createCode(p.value)}>
            Create {p.label} link code
          </Button>
        ))}
      </Space>
      {error !== null ? <Alert type="error" showIcon title={errorMessage(error)} /> : null}
      {issued && instruction ? (
        <Alert
          type="info"
          showIcon
          title={`${chatProviderLabel(issued.provider)} link code`}
          closable={{
            onClose: () => {
              setIssued(null);
              void queryClient.invalidateQueries({ queryKey: qk.myProviderLinks });
            },
          }}
          description={
            <Space orientation="vertical" size={8} style={{ width: '100%' }}>
              <span>
                {instruction.where} Single use; expires in <Countdown deadline={issued.expires_at} />.
              </span>
              <CopyField label="Command to send" value={instruction.command} />
              {instruction.caution ? <strong>{instruction.caution}</strong> : null}
              <span>After the bot confirms, close this notice to refresh the list.</span>
            </Space>
          }
        />
      ) : null}
    </Space>
  );
}
