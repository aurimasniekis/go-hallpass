import { CopyOutlined } from '@ant-design/icons';
import { Button } from 'antd';

import { useCopy } from './useCopy';

export interface FingerprintProps {
  /** Full fingerprint, e.g. `SHA256:…`. Never truncated: operators compare it out of band. */
  value: string;
  label?: string;
  copyable?: boolean;
}

export function Fingerprint({ value, label = 'Fingerprint', copyable = true }: FingerprintProps) {
  const copy = useCopy();
  return (
    <span className="hp-fingerprint">
      <code aria-label={`${label}: ${value}`}>{value}</code>
      {copyable ? (
        <Button
          size="small"
          type="text"
          icon={<CopyOutlined />}
          aria-label={`Copy ${label.toLowerCase()}`}
          onClick={() => {
            void copy(value, label);
          }}
        />
      ) : null}
    </span>
  );
}
