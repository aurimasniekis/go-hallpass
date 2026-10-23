import { describe, expect, it } from 'vitest';

import {
  emptySelectorForm,
  formToSelector,
  isSelectorEmpty,
  selectorToForm,
  summarizeSelector,
  type SelectorKind,
} from './model';

describe('selector model', () => {
  it('round-trips every kind through the form state', () => {
    const cases: [SelectorKind, Record<string, unknown>][] = [
      [
        'subject',
        {
          agents: ['agt_1'],
          agent_groups: ['ci'],
          agent_labels: {
            matchLabels: { env: 'prod' },
            matchExpressions: [
              { key: 'team', operator: 'In', values: ['a', 'b'] },
              { key: 'legacy', operator: 'DoesNotExist' },
            ],
          },
        },
      ],
      ['target', { all: true, servers: ['srv_1'], server_groups: ['db'] }],
      ['role', { names: ['admin'], ids: ['rol_1'], role_labels: { matchLabels: { class: 'ro' } } }],
      ['operator', { operators: ['op_1'], operator_groups: ['oncall'] }],
    ];
    for (const [kind, wire] of cases) {
      const { selector, errors } = formToSelector(kind, selectorToForm(kind, wire));
      expect(errors).toEqual([]);
      expect(selector).toEqual(wire);
    }
  });

  it('only emits fields that belong to the kind (server rejects unknown fields)', () => {
    const form = { ...emptySelectorForm(), ids: ['x'], groups: ['g'], names: ['n'], labels: ['a=b'] };
    expect(formToSelector('operator', form).selector).toEqual({ operators: ['x'], operator_groups: ['g'] });
    expect(formToSelector('role', form).selector).toEqual({
      ids: ['x'],
      names: ['n'],
      role_labels: { matchLabels: { a: 'b' } },
    });
  });

  it('detects empty selectors, which match nothing', () => {
    expect(isSelectorEmpty('target', emptySelectorForm())).toBe(true);
    expect(isSelectorEmpty('target', { ...emptySelectorForm(), ids: ['  '] })).toBe(true);
    expect(isSelectorEmpty('target', { ...emptySelectorForm(), all: true })).toBe(false);
    // Role selectors have no group clause: groups alone are still empty.
    expect(isSelectorEmpty('role', { ...emptySelectorForm(), groups: ['g'] })).toBe(true);
  });

  it('validates label expressions and key=value labels', () => {
    const form = {
      ...emptySelectorForm(),
      labels: ['novalue'],
      expressions: [
        { key: 'team', operator: 'In' as const, values: [] },
        { key: 'x', operator: 'Exists' as const, values: ['y'] },
        { key: ' ', operator: 'NotIn' as const, values: ['z'] },
      ],
    };
    const { errors } = formToSelector('subject', form);
    expect(errors).toHaveLength(4);
    expect(errors[0]).toMatch(/key=value/);
  });

  it('ignores malformed wire data instead of crashing', () => {
    const form = selectorToForm('subject', {
      agents: ['a', 3],
      agent_labels: {
        matchLabels: { ok: 'y', bad: 1 },
        matchExpressions: [{ key: 'k', operator: 'Nope' }, 'x'],
      },
    });
    expect(form.ids).toEqual(['a']);
    expect(form.labels).toEqual(['ok=y']);
    expect(form.expressions).toEqual([]);
    expect(selectorToForm('target', null)).toEqual(emptySelectorForm());
  });

  it('summarizes selectors for tables', () => {
    expect(summarizeSelector('target', {})).toBe('No servers (empty selector)');
    expect(summarizeSelector('target', { all: true })).toBe('All servers');
    expect(
      summarizeSelector(
        'subject',
        {
          agents: ['agt_1'],
          agent_labels: {
            matchLabels: { env: 'prod' },
            matchExpressions: [{ key: 't', operator: 'NotIn', values: ['a'] }],
          },
        },
        (id) => (id === 'agt_1' ? 'builder' : id),
      ),
    ).toBe('agent: builder; labels: env=prod and t not in (a)');
  });
});
