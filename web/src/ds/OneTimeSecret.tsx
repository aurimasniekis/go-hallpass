import { CopyOutlined } from '@ant-design/icons';
import { Alert, Button, Checkbox, Modal, Space } from 'antd';
import { useId, useState, type ReactNode } from 'react';

import { useCopy } from './useCopy';

export interface OneTimeSecretProps {
  open: boolean;
  title: ReactNode;
  /** What the value is and what to do with it. */
  description?: ReactNode;
  /** One value (token, URL) or several (recovery codes). */
  values: readonly string[];
  /** Label used for copy feedback and the accessible name of the list. */
  label: string;
  /** Called after the operator confirmed they stored the value. The caller must then drop it. */
  onClose: () => void;
}

/**
 * Shows a secret the server returns exactly once (reset tokens, invitations, recovery codes). The dialog
 * cannot be dismissed until the operator confirms they stored it; the value is never persisted by the UI.
 */
export function OneTimeSecret({ open, title, description, values, label, onClose }: OneTimeSecretProps) {
  const copy = useCopy();
  const [stored, setStored] = useState(false);
  const listId = useId();
  const close = () => {
    setStored(false);
    onClose();
  };
  return (
    <Modal
      open={open}
      title={title}
      closable={false}
      mask={{ closable: false }}
      keyboard={false}
      destroyOnHidden
      footer={[
        <Button
          key="copy"
          icon={<CopyOutlined />}
          onClick={() => {
            void copy(values.join('\n'), label);
          }}
        >
          Copy
        </Button>,
        <Button key="done" type="primary" disabled={!stored} onClick={close}>
          Done
        </Button>,
      ]}
    >
      <Space orientation="vertical" size={12} style={{ width: '100%' }}>
        <Alert
          type="warning"
          showIcon
          title="Shown only once"
          description="Hallpass stores only a hash. Copy it now; it cannot be displayed again."
        />
        {description ? <div>{description}</div> : null}
        <ul id={listId} aria-label={label} className="hp-secret-list">
          {values.map((v, i) => (
            <li key={`${String(i)}-${v}`}>
              <code className="hp-mono">{v}</code>
            </li>
          ))}
        </ul>
        <Checkbox
          checked={stored}
          onChange={(e) => {
            setStored(e.target.checked);
          }}
        >
          I have stored this securely
        </Checkbox>
      </Space>
    </Modal>
  );
}
