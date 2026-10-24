/** Chat providers that accept self-service link codes (HP-NTF-011, docs/operator/approvals.md). */
export type ChatProvider = 'slack' | 'telegram';

export interface LinkInstruction {
  /** Exact text to send to the bot. */
  command: string;
  /** Where to send it. */
  where: string;
  /** Extra caution shown with the code. */
  caution?: string;
}

export function linkInstruction(provider: ChatProvider, code: string): LinkInstruction {
  if (provider === 'slack') {
    return {
      command: `/hallpass link ${code}`,
      where: 'Run this slash command in any Slack channel or direct message in the linked workspace.',
    };
  }
  return {
    command: `/link ${code}`,
    where: 'Send this message in a private chat with the HallPass Telegram bot.',
    caution: 'Never post it in a group: a code seen in a group chat is burned and cannot be used.',
  };
}
