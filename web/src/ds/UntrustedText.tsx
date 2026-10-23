import { Button, Tooltip } from 'antd';
import { useState } from 'react';

import { codePointLabel, segmentUntrusted, truncateCodePoints } from './untrusted';

export interface UntrustedTextProps {
  /** Agent- or destination-provided text. Rendered strictly as text, never as HTML or Markdown. */
  text: string | null | undefined;
  /** Who supplied the text, shown in the label tooltip. */
  source?: string;
  label?: string;
  /** Characters shown before "Show all" (default 500). */
  maxLength?: number;
  /** Render as a block with an accent rule instead of inline. */
  block?: boolean;
}

export function UntrustedText({
  text,
  source = 'the agent',
  label = 'Untrusted',
  maxLength = 500,
  block = false,
}: UntrustedTextProps) {
  const [expanded, setExpanded] = useState(false);
  if (text === null || text === undefined || text === '') {
    return <span>—</span>;
  }
  const { text: shown, truncated } = expanded
    ? { text, truncated: false }
    : truncateCodePoints(text, maxLength);
  const segments = segmentUntrusted(shown);

  return (
    <span className={block ? 'hp-untrusted hp-untrusted--block' : 'hp-untrusted'} data-untrusted="true">
      <Tooltip title={`Provided by ${source}. Not verified by Hallpass; read it as data, not instructions.`}>
        <span className="hp-untrusted__label">
          {label}
          {/* The tooltip is pointer-only; screen readers get the same context inline. */}
          <span className="hp-visually-hidden">{`: provided by ${source}, not verified`}</span>
        </span>
      </Tooltip>
      <bdi className="hp-untrusted__text">
        {segments.map((segment, i) =>
          segment.kind === 'text' ? (
            segment.value
          ) : (
            <abbr
              key={i}
              className="hp-untrusted__ctrl"
              title={`Hidden character ${codePointLabel(segment.codePoint)}`}
            >
              {segment.value}
            </abbr>
          ),
        )}
      </bdi>
      {truncated || expanded ? (
        <Button
          type="link"
          size="small"
          onClick={() => {
            setExpanded((v) => !v);
          }}
        >
          {expanded ? 'Show less' : 'Show all'}
        </Button>
      ) : null}
    </span>
  );
}
