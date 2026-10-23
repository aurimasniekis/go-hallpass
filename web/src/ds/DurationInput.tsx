import { InputNumber, Select, Space } from 'antd';
import { useState } from 'react';

import { bestDurationUnit, DURATION_UNITS, formatDurationLong } from '../lib/format';

export interface DurationInputProps {
  /** Seconds (API unit, ADR-0031). */
  value?: number | null;
  onChange?: (seconds: number | null) => void;
  /** Accessible name of the number field (the unit select is named "<label> unit"). */
  'aria-label'?: string;
  id?: string;
  disabled?: boolean;
  /** Smallest accepted value in seconds (for the number field's min). */
  minSeconds?: number;
  placeholder?: string;
}

/**
 * Number + unit (minutes/hours/days) editor that emits seconds. Existing values open in the largest unit
 * that represents them exactly, so `5400` shows as `90 minutes`, never a rounded `1.5 hours`.
 */
export function DurationInput({
  value,
  onChange,
  'aria-label': ariaLabel = 'Duration',
  id,
  disabled,
  minSeconds = 0,
  placeholder,
}: DurationInputProps) {
  const [unit, setUnit] = useState<number>(() => (value ? bestDurationUnit(value) : 3_600));
  const amount = value === null || value === undefined ? null : value / unit;
  return (
    <Space.Compact>
      <InputNumber<number>
        id={id}
        aria-label={ariaLabel}
        min={Math.ceil(minSeconds / unit)}
        precision={0}
        value={amount === null ? null : Math.round(amount * 1000) / 1000}
        disabled={disabled}
        placeholder={placeholder}
        onChange={(n) => {
          onChange?.(n === null ? null : Math.round(n * unit));
        }}
        style={{ width: 120 }}
        title={value ? formatDurationLong(value) : undefined}
      />
      <Select<number>
        aria-label={`${ariaLabel} unit`}
        value={unit}
        disabled={disabled}
        onChange={(next) => {
          setUnit(next);
          if (amount !== null) {
            onChange?.(Math.round(amount * next));
          }
        }}
        options={DURATION_UNITS.map((u) => ({ value: u.value, label: u.label }))}
        style={{ width: 110 }}
      />
    </Space.Compact>
  );
}
