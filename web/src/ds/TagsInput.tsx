import { Select } from 'antd';

export interface TagsInputProps {
  value?: string[] | null;
  onChange?: (value: string[]) => void;
  'aria-label'?: string;
  id?: string;
  placeholder?: string;
  disabled?: boolean;
  /** Suggestions (e.g. existing group names); free text is always allowed. */
  options?: readonly { value: string; label?: string }[];
  /** Characters that end an entry while typing (default comma and space). */
  tokenSeparators?: string[];
}

/** Free-form list editor (groups, CIDRs, principals, label `key=value` pairs). */
export function TagsInput({
  value,
  onChange,
  options,
  tokenSeparators = [',', ' '],
  ...rest
}: TagsInputProps) {
  return (
    <Select<string[]>
      mode="tags"
      value={value ?? []}
      onChange={(v) => onChange?.(v)}
      tokenSeparators={tokenSeparators}
      open={options && options.length > 0 ? undefined : false}
      suffix={null}
      options={options?.map((o) => ({ value: o.value, label: o.label ?? o.value }))}
      style={{ width: '100%' }}
      {...rest}
    />
  );
}
