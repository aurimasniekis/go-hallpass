import { CopyOutlined } from '@ant-design/icons';
import { Button, Input, Space, Tooltip } from 'antd';
import { useId } from 'react';

import { useCopy } from './useCopy';

export interface CopyFieldProps {
  label: string;
  value: string;
  /** Render the value in the monospace face (URLs, IDs, keys). */
  monospace?: boolean;
  /** Keep the label for assistive technology only (dense tables whose column header names the value). */
  hideLabel?: boolean;
}

/** Read-only value with a copy button (e.g. the OIDC callback URL). */
export function CopyField({ label, value, monospace = true, hideLabel = false }: CopyFieldProps) {
  const copy = useCopy();
  const id = useId();
  return (
    <div>
      <label
        htmlFor={id}
        className={hideLabel ? 'hp-visually-hidden' : undefined}
        style={hideLabel ? undefined : { display: 'block', marginBottom: 4 }}
      >
        {label}
      </label>
      <Space.Compact style={{ width: '100%' }}>
        <Input
          id={id}
          readOnly
          value={value}
          className={monospace ? 'hp-mono' : undefined}
          style={{ minWidth: 0 }}
        />
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
