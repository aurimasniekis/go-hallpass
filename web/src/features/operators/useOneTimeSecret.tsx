import { useState, type ReactNode } from 'react';

import { OneTimeSecret } from '../../ds/OneTimeSecret';

interface Shown {
  title: ReactNode;
  label: string;
  description?: ReactNode;
  values: string[];
}

/**
 * Holds a one-time secret only while its dialog is open; closing the dialog drops it from state, so the
 * value cannot be shown again (the server keeps only a hash).
 */
export function useOneTimeSecret(): { show: (s: Shown) => void; dialog: ReactNode } {
  const [shown, setShown] = useState<Shown | null>(null);
  const dialog = (
    <OneTimeSecret
      open={shown !== null}
      title={shown?.title ?? ''}
      label={shown?.label ?? 'Secret'}
      description={shown?.description}
      values={shown?.values ?? []}
      onClose={() => {
        setShown(null);
      }}
    />
  );
  return { show: setShown, dialog };
}
