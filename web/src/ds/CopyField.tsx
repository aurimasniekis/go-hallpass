import { CopyOutlined } from '@ant-design/icons';
import { Button, Input, Space, Tooltip } from 'antd';
import { useId } from 'react';

import { useCopy } from './useCopy';

export interface CopyFieldProps {
  label: string;
  value: string;
  /** Render the value in the monospace face (URLs, IDs, keys). */
  monospace?: boolean;
}

/** Read-only value with a copy button (e.g. the OIDC callback URL). */
export function CopyField({ label, value, monospace = true }: CopyFieldProps) {
  const copy = useCopy();
  const id = useId();
  return (
    <div>
      <label htmlFor={id} style={{ display: 'block', marginBottom: 4 }}>
        {label}
      </label>
      <Space.Compact style={{ width: '100%' }}>
        <Input id={id} readOnly value={value} className={monospace ? 'hp-mono' : undefined} />
        <Tooltip title={`Copy ${label.toLowerCase()}`}>
          <Button
            icon={<CopyOutlined />}
            aria-label={`Copy ${label}`}
            onClick={() => {
              void copy(value, label);
            }}
          />
        </Tooltip>
      </Space.Compact>
    </div>
  );
}
