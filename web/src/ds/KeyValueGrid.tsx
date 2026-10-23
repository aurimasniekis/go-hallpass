import type { CSSProperties, ReactNode } from 'react';

export interface KeyValueItem {
  key: string;
  label: ReactNode;
  value: ReactNode;
  /**
   * Long values (IDs, descriptions, reasons) take two columns when the panel is wide enough, or the
   * whole row with `'full'`.
   */
  span?: 2 | 'full';
}

export interface KeyValueGridProps {
  items: readonly KeyValueItem[];
  /**
   * Maximum number of columns. The grid is responsive to the width of its panel (not the viewport): it
   * shows as many columns of at least `minColumnWidth` as fit, up to this cap. Default 6.
   */
  columns?: number;
  /** Narrowest column in pixels before the grid drops a column. Default 180. */
  minColumnWidth?: number;
}

/** Description list for detail pages. Empty values render an explicit em dash. */
export function KeyValueGrid({ items, columns = 6, minColumnWidth = 180 }: KeyValueGridProps) {
  return (
    <dl
      className="hp-kv"
      style={
        {
          '--hp-kv-columns': Math.max(1, Math.floor(columns)),
          '--hp-kv-min': `${String(minColumnWidth)}px`,
        } as CSSProperties
      }
    >
      {items.map((item) => (
        <div
          className={`hp-kv__item${item.span === 'full' ? ' hp-kv__item--full' : item.span === 2 ? ' hp-kv__item--wide' : ''}`}
          key={item.key}
        >
          <dt>{item.label}</dt>
          <dd>{item.value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  );
}
