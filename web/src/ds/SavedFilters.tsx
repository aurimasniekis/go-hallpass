import { DeleteOutlined, SaveOutlined } from '@ant-design/icons';
import { Button, Input, Popover, Select, Space, Tooltip } from 'antd';
import { useId, useState } from 'react';

import { deleteFilter, saveFilter, useSavedFilters, type FilterValues } from '../stores/savedFilters';

export interface SavedFiltersProps {
  /** Table identifier (`requests`, `sessions`, `audit`). */
  table: string;
  /** Current filter values (URL search params). */
  current: FilterValues;
  onApply: (filters: FilterValues) => void;
}

/** Named, locally persisted filter presets for server-filtered tables (HP-UI-008). */
export function SavedFilters({ table, current, onApply }: SavedFiltersProps) {
  const saved = useSavedFilters(table);
  const [selected, setSelected] = useState<string | undefined>(undefined);
  const [name, setName] = useState('');
  const [open, setOpen] = useState(false);
  const nameId = useId();
  const hasFilters = Object.values(current).some((v) => v !== '');

  return (
    <Space.Compact>
      <Select<string>
        aria-label="Saved filters"
        placeholder="Saved filters"
        value={selected}
        allowClear
        style={{ minWidth: 180 }}
        options={saved.map((f) => ({ value: f.name, label: f.name }))}
        notFoundContent="No saved filters"
        onChange={(value) => {
          setSelected(value);
          const match = saved.find((f) => f.name === value);
          if (match) {
            onApply(match.filters);
          }
        }}
      />
      <Popover
        open={open}
        onOpenChange={setOpen}
        trigger="click"
        title="Save current filters"
        content={
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (name.trim() !== '') {
                saveFilter(table, name.trim(), current);
                setSelected(name.trim());
                setName('');
                setOpen(false);
              }
            }}
          >
            <label htmlFor={nameId} style={{ display: 'block', marginBottom: 4 }}>
              Name
            </label>
            <Space.Compact>
              <Input
                id={nameId}
                value={name}
                maxLength={64}
                onChange={(e) => {
                  setName(e.target.value);
                }}
              />
              <Button type="primary" htmlType="submit" disabled={name.trim() === ''}>
                Save
              </Button>
            </Space.Compact>
          </form>
        }
      >
        <Tooltip title={hasFilters ? 'Save current filters' : 'Set a filter first'}>
          <Button icon={<SaveOutlined />} aria-label="Save current filters" disabled={!hasFilters} />
        </Tooltip>
      </Popover>
      <Tooltip title="Delete selected saved filter">
        <Button
          icon={<DeleteOutlined />}
          aria-label="Delete selected saved filter"
          disabled={selected === undefined}
          onClick={() => {
            if (selected !== undefined) {
              deleteFilter(table, selected);
              setSelected(undefined);
            }
          }}
        />
      </Tooltip>
    </Space.Compact>
  );
}
