import type { CSSProperties, ReactNode } from 'react';

export interface KeyValueItem {
  key: string;
  label: ReactNode;
  value: ReactNode;
}

export interface KeyValueGridProps {
  items: readonly KeyValueItem[];
  columns?: 1 | 2 | 3 | 4;
}

/** Description list for detail pages. Empty values render an explicit em dash. */
export function KeyValueGrid({ items, columns = 2 }: KeyValueGridProps) {
  return (
    <dl className="hp-kv" style={{ '--hp-kv-columns': columns } as CSSProperties}>
      {items.map((item) => (
        <div className="hp-kv__item" key={item.key}>
          <dt>{item.label}</dt>
          <dd>{item.value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  );
}
