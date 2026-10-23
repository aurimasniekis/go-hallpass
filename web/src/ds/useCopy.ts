import { App } from 'antd';
import { useCallback } from 'react';

/** Copies text to the clipboard and reports the outcome; failures are reported, never hidden. */
export function useCopy(): (text: string, what?: string) => Promise<boolean> {
  const { message } = App.useApp();
  return useCallback(
    async (text: string, what = 'Value') => {
      try {
        await navigator.clipboard.writeText(text);
        void message.success(`${what} copied`);
        return true;
      } catch {
        void message.error(`Could not copy ${what.toLowerCase()}; select and copy it manually`);
        return false;
      }
    },
    [message],
  );
}
