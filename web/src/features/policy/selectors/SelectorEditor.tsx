import { DeleteOutlined, PlusOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Alert, Button, Checkbox, Input, Select, Space } from 'antd';
import { useId, type CSSProperties } from 'react';

import {
  agentsQueryOptions,
  groupsQueryOptions,
  operatorsQueryOptions,
  serversQueryOptions,
} from '../../../api/queries';
import { TagsInput } from '../../../ds/TagsInput';
import { usePermissions } from '../../../lib/usePermissions';
import {
  emptySelectorForm,
  isSelectorEmpty,
  KIND_FIELDS,
  KIND_NOUN,
  LABEL_OPERATORS,
  type LabelExpression,
  type SelectorForm,
  type SelectorKind,
} from './model';

const FIELDSET_STYLE: CSSProperties = {
  border: '1px solid var(--hp-color-border-secondary)',
  borderRadius: 6,
  padding: '8px 12px 12px',
  margin: '0 0 16px',
  display: 'grid',
  gap: 10,
  minWidth: 0,
};
const LEGEND_STYLE: CSSProperties = {
  padding: '0 4px',
  fontWeight: 600,
  width: 'auto',
  margin: 0,
  fontSize: 14,
};
const ROW_STYLE: CSSProperties = { display: 'grid', gap: 4 };

interface Option {
  value: string;
  label: string;
}

/** ID and group suggestions for a selector kind, from lists the operator may read (free text otherwise). */
export function useSelectorOptions(kind: SelectorKind): { ids: Option[]; groups: Option[] } {
  const { can } = usePermissions();
  const inv = can('inventory.read');
  const agents = useQuery({ ...agentsQueryOptions(), enabled: inv && kind === 'subject' });
  const servers = useQuery({ ...serversQueryOptions(), enabled: inv && kind === 'target' });
  const operators = useQuery({
    ...operatorsQueryOptions(),
    enabled: kind === 'operator' && can('operators.manage'),
  });
  const groupKind =
    kind === 'subject'
      ? 'agent'
      : kind === 'target'
        ? 'server'
        : kind === 'operator'
          ? 'operator'
          : undefined;
  const groups = useQuery({ ...groupsQueryOptions(groupKind), enabled: inv && groupKind !== undefined });

  let ids: Option[] = [];
  if (kind === 'subject') {
    ids = (agents.data?.items ?? []).map((a) => ({ value: a.id, label: `${a.name} (${a.id})` }));
  } else if (kind === 'target') {
    ids = (servers.data?.items ?? []).map((s) => ({ value: s.id, label: `${s.alias} (${s.id})` }));
  } else if (kind === 'operator') {
    ids = (operators.data?.items ?? []).map((o) => ({
      value: o.id,
      label: o.email ? `${o.display_name} <${o.email}>` : o.display_name,
    }));
  }
  const groupOptions = [...new Set((groups.data?.items ?? []).map((g) => g.name))].map((name) => ({
    value: name,
    label: name,
  }));
  return { ids, groups: groupOptions };
}

function ExpressionRow({
  expression,
  index,
  onChange,
  onRemove,
  disabled,
}: {
  expression: LabelExpression;
  index: number;
  onChange: (e: LabelExpression) => void;
  onRemove: () => void;
  disabled?: boolean | undefined;
}) {
  const needsValues = expression.operator === 'In' || expression.operator === 'NotIn';
  const n = String(index + 1);
  return (
    <Space wrap align="start">
      <Input
        aria-label={`Expression ${n} label key`}
        placeholder="key"
        value={expression.key}
        disabled={disabled}
        onChange={(e) => {
          onChange({ ...expression, key: e.target.value });
        }}
        style={{ width: 140 }}
      />
      <Select<LabelExpression['operator']>
        aria-label={`Expression ${n} operator`}
        value={expression.operator}
        disabled={disabled}
        onChange={(operator) => {
          onChange({
            ...expression,
            operator,
            values: operator === 'In' || operator === 'NotIn' ? expression.values : [],
          });
        }}
        options={LABEL_OPERATORS.map((o) => ({ value: o, label: o }))}
        style={{ width: 140 }}
      />
      {needsValues ? (
        <div style={{ minWidth: 200 }}>
          <TagsInput
            aria-label={`Expression ${n} values`}
            placeholder="values"
            value={expression.values}
            disabled={disabled}
            onChange={(values) => {
              onChange({ ...expression, values });
            }}
          />
        </div>
      ) : null}
      <Button
        icon={<DeleteOutlined />}
        aria-label={`Remove expression ${n}`}
        disabled={disabled}
        onClick={onRemove}
      />
    </Space>
  );
}

export interface SelectorEditorProps {
  kind: SelectorKind;
  /** Fieldset legend, e.g. "Agents (subjects)". */
  legend: string;
  value?: SelectorForm;
  onChange?: (value: SelectorForm) => void;
  disabled?: boolean;
}

/**
 * Editor for a policy selector (HP-POL-003). Clauses are unioned; a label selector requires every
 * `key=value` and every expression. An empty selector matches nothing, which the editor states plainly.
 */
export function SelectorEditor({ kind, legend, value, onChange, disabled }: SelectorEditorProps) {
  const form = value ?? emptySelectorForm();
  const fields = KIND_FIELDS[kind];
  const noun = KIND_NOUN[kind];
  const options = useSelectorOptions(kind);
  const base = useId();
  const set = (patch: Partial<SelectorForm>) => {
    onChange?.({ ...form, ...patch });
  };
  const labelId = (s: string) => `${base}-${s}`;

  return (
    <fieldset style={FIELDSET_STYLE} disabled={disabled}>
      <legend style={LEGEND_STYLE}>{legend}</legend>
      <Checkbox
        checked={form.all}
        onChange={(e) => {
          set({ all: e.target.checked });
        }}
      >
        All {noun.many} (including {noun.many} created later)
      </Checkbox>
      <div style={ROW_STYLE}>
        <label htmlFor={labelId('ids')}>{kind === 'role' ? 'Role IDs' : `Specific ${noun.many}`}</label>
        <TagsInput
          id={labelId('ids')}
          aria-label={kind === 'role' ? 'Role IDs' : `Specific ${noun.many}`}
          placeholder={options.ids.length ? `Choose ${noun.many}` : `${noun.one} IDs`}
          value={form.ids}
          options={options.ids}
          onChange={(ids) => {
            set({ ids });
          }}
        />
      </div>
      {fields.names ? (
        <div style={ROW_STYLE}>
          <label htmlFor={labelId('names')}>Role names (aliases)</label>
          <TagsInput
            id={labelId('names')}
            aria-label="Role names (aliases)"
            placeholder="e.g. admin, readonly"
            value={form.names}
            onChange={(names) => {
              set({ names });
            }}
          />
        </div>
      ) : null}
      {fields.groups ? (
        <div style={ROW_STYLE}>
          <label
            htmlFor={labelId('groups')}
          >{`${noun.one[0]?.toUpperCase() ?? ''}${noun.one.slice(1)} groups`}</label>
          <TagsInput
            id={labelId('groups')}
            aria-label={`${noun.one} groups`}
            placeholder="group names"
            value={form.groups}
            options={options.groups}
            onChange={(groups) => {
              set({ groups });
            }}
          />
        </div>
      ) : null}
      {fields.labels ? (
        <>
          <div style={ROW_STYLE}>
            <label htmlFor={labelId('labels')}>Labels (all must match, key=value)</label>
            <TagsInput
              id={labelId('labels')}
              aria-label="Labels (key=value)"
              placeholder="env=prod"
              value={form.labels}
              onChange={(labels) => {
                set({ labels });
              }}
            />
          </div>
          <div style={ROW_STYLE}>
            <span>Label expressions</span>
            <Space orientation="vertical" style={{ width: '100%' }}>
              {form.expressions.map((e, i) => (
                <ExpressionRow
                  // Expressions have no identity beyond their position.
                  key={i}
                  index={i}
                  expression={e}
                  disabled={disabled}
                  onChange={(next) => {
                    set({ expressions: form.expressions.map((x, j) => (j === i ? next : x)) });
                  }}
                  onRemove={() => {
                    set({ expressions: form.expressions.filter((_x, j) => j !== i) });
                  }}
                />
              ))}
              <Button
                size="small"
                icon={<PlusOutlined />}
                disabled={disabled}
                onClick={() => {
                  set({ expressions: [...form.expressions, { key: '', operator: 'In', values: [] }] });
                }}
              >
                Add expression
              </Button>
            </Space>
          </div>
        </>
      ) : null}
      {isSelectorEmpty(kind, form) ? (
        <Alert
          type="warning"
          showIcon
          title={`This selector is empty and matches no ${noun.many}.`}
          description={`Select ${noun.many}${fields.groups ? ', groups' : ''}${fields.labels ? ', labels' : ''}, or choose "All ${noun.many}".`}
        />
      ) : null}
    </fieldset>
  );
}
