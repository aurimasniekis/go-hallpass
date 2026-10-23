import { CopyOutlined } from '@ant-design/icons';
import { Button, Tooltip } from 'antd';

import { useCopy } from './useCopy';

export interface CodeBlockProps {
  /** Command or file content. Rendered as text only. */
  code: string;
  /** What is copied, for the button label and the toast (e.g. "Command"). */
  label?: string;
}

/** Preformatted command with a copy button (setup instructions). */
export function CodeBlock({ code, label = 'Command' }: CodeBlockProps) {
  const copy = useCopy();
  return (
    <div className="hp-code">
      <pre className="hp-code__pre">
        <code>{code}</code>
      </pre>
      <Tooltip title={`Copy ${label.toLowerCase()}`}>
        <Button
          className="hp-code__copy"
          size="small"
          type="text"
          icon={<CopyOutlined />}
          aria-label={`Copy ${label.toLowerCase()}`}
          onClick={() => {
            void copy(code, label);
          }}
        />
      </Tooltip>
    </div>
  );
}
