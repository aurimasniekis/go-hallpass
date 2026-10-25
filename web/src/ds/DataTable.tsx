import { DownOutlined, LeftOutlined, RightOutlined, UpOutlined } from '@ant-design/icons';
import { Alert, Button, Select, Spin, Table, type TableColumnsType, type TableProps } from 'antd';
import type { SorterResult } from 'antd/es/table/interface';
import { isValidElement, useMemo, useState, type Key, type ReactNode } from 'react';

import { NARROW_QUERY, useMediaQuery } from '../lib/useMediaQuery';
import { useDensity } from '../stores/density';
import { EmptyState, ErrorState } from './states';

/**
 * Server-driven table (docs/PLAN.md §8.1, §14.2; HP-UI-007, HP-UI-008).
 *
 * Sorting, filtering and pagination are *controlled* and delegated to the server: this component never
 * sorts or filters rows locally. Pagination is cursor-based (`{items, next_cursor}`), so the caller keeps
 * a cursor stack and exposes previous/next.
 *
 * States: initial loading, empty, error (403 → permission denied), refresh failure while showing the last
 * loaded rows, and stale (live updates disconnected).
 */

export interface SortState {
  /** Column key as accepted by the API's `sort` allowlist. */
  field: string;
  order: 'ascend' | 'descend';
}

/** `{field:'created_at', order:'descend'}` → `-created_at` (API sort syntax). */
export function toSortParam(sort: SortState | null | undefined): string | undefined {
  if (!sort) {
    return undefined;
  }
  return sort.order === 'descend' ? `-${sort.field}` : sort.field;
}

/** Inverse of `toSortParam`, for reading sort state from URL search params. */
export function fromSortParam(param: string | null | undefined): SortState | null {
  if (!param) {
    return null;
  }
  return param.startsWith('-')
    ? { field: param.slice(1), order: 'descend' }
    : { field: param, order: 'ascend' };
}

export type FilterState = Record<string, readonly string[] | null>;

export interface CursorPagination {
  pageSize: number;
  pageSizeOptions?: readonly number[];
  hasPreviousPage: boolean;
  hasNextPage: boolean;
  onPreviousPage: () => void;
  onNextPage: () => void;
  onPageSizeChange?: (size: number) => void;
}

export interface DataTableProps<T extends object> {
  /** Accessible name of the table region. */
  caption: string;
  columns: TableColumnsType<T>;
  rows: readonly T[] | undefined;
  rowKey: Extract<keyof T, string> | ((row: T) => string);
  /** First load (no rows yet). */
  loading?: boolean;
  /** Background refetch in progress. */
  fetching?: boolean;
  error?: unknown;
  onRetry?: () => void;
  /** Live updates are down; rows may be out of date. */
  stale?: boolean;
  emptyTitle?: ReactNode;
  emptyDescription?: ReactNode;
  sort?: SortState | null;
  onSortChange?: (sort: SortState | null) => void;
  filters?: FilterState;
  onFiltersChange?: (filters: FilterState) => void;
  pagination?: CursorPagination;
  onRowClick?: (row: T) => void;
  /** Note rendered under the table (legends, hints). */
  footer?: ReactNode;
  /** Expandable rows (details rendered under a row). */
  expandable?: TableProps<T>['expandable'];
}

function columnKey<T>(column: TableColumnsType<T>[number]): string | undefined {
  if (column.key !== undefined) {
    return String(column.key);
  }
  if ('dataIndex' in column && typeof column.dataIndex === 'string') {
    return column.dataIndex;
  }
  return undefined;
}

type Column<T> = TableColumnsType<T>[number];

/** An actions column: a visually hidden title (icon buttons, menus) or the conventional `actions` key. */
function isActionsColumn<T>(column: Column<T>): boolean {
  if (column.key === 'actions') {
    return true;
  }
  const t = column.title;
  if (isValidElement<{ className?: string }>(t)) {
    return (t.props.className ?? '').includes('hp-visually-hidden');
  }
  return t === undefined || t === null || t === '';
}

function cellValue<T extends object>(column: Column<T>, row: T, index: number): ReactNode {
  const dataIndex = 'dataIndex' in column ? column.dataIndex : undefined;
  let value: unknown;
  if (typeof dataIndex === 'string' || typeof dataIndex === 'number') {
    value = (row as Record<string | number, unknown>)[dataIndex];
  } else if (Array.isArray(dataIndex)) {
    value = dataIndex.reduce<unknown>((v, k) => (v as Record<string, unknown> | undefined)?.[String(k)], row);
  }
  if (column.render) {
    const out: unknown = column.render(value, row, index);
    // A render may return {children, props} to set cell props; only the content matters here.
    if (out !== null && typeof out === 'object' && !isValidElement(out) && 'children' in out) {
      return (out as { children: ReactNode }).children;
    }
    return out as ReactNode;
  }
  return value === undefined || value === null ? null : (value as ReactNode);
}

function CardRow<T extends object>({
  row,
  index,
  columns,
  onRowClick,
  expandable,
}: {
  row: T;
  index: number;
  columns: TableColumnsType<T>;
  onRowClick?: (row: T) => void;
  expandable?: TableProps<T>['expandable'];
}) {
  const [open, setOpen] = useState(false);
  const fields = columns.filter((c) => !isActionsColumn(c));
  const actions = columns.filter((c) => isActionsColumn(c));
  const details = expandable?.expandedRowRender && (expandable.rowExpandable?.(row) ?? true);
  return (
    <li
      className="hp-card-row"
      {...(onRowClick
        ? {
            onClick: () => {
              onRowClick(row);
            },
            style: { cursor: 'pointer' },
          }
        : {})}
    >
      <dl>
        {fields.map((c, i) => (
          <div key={String(c.key ?? i)} className="hp-card-row__field">
            <dt>{typeof c.title === 'function' ? null : c.title}</dt>
            <dd>{cellValue(c, row, index)}</dd>
          </div>
        ))}
      </dl>
      {actions.length > 0 || details ? (
        <div className="hp-card-row__actions">
          {details ? (
            <Button
              size="small"
              type="link"
              icon={open ? <UpOutlined /> : <DownOutlined />}
              onClick={(e) => {
                e.stopPropagation();
                setOpen((v) => !v);
              }}
            >
              {open ? 'Hide details' : 'Details'}
            </Button>
          ) : null}
          {actions.map((c, i) => (
            <span key={String(c.key ?? i)}>{cellValue(c, row, index)}</span>
          ))}
        </div>
      ) : null}
      {details && open && expandable.expandedRowRender ? (
        <div className="hp-card-row__details">{expandable.expandedRowRender(row, index, 0, true)}</div>
      ) : null}
    </li>
  );
}

/**
 * Drop-in for antd's Table on small, local tables (keys, previews, settings): the same props, rendered as one card
 * per row on phones. Use DataTable for server-driven lists.
 */
export function ResponsiveTable<T extends object>(props: TableProps<T>) {
  const narrow = useMediaQuery(NARROW_QUERY);
  if (!narrow) {
    return <Table<T> {...props} />;
  }
  const rows = props.dataSource ?? [];
  const columns = props.columns ?? [];
  const keyOf = (row: T, index: number): string => {
    const rk = props.rowKey;
    if (typeof rk === 'function') {
      return String(rk(row, index));
    }
    if (rk !== undefined) {
      return String((row as Record<string, unknown>)[rk as string]);
    }
    const k = (row as { key?: string | number }).key;
    return k === undefined ? String(index) : String(k);
  };
  if (props.loading && rows.length === 0) {
    return (
      <div className="hp-cards__loading">
        <Spin />
      </div>
    );
  }
  if (rows.length === 0) {
    const empty = props.locale?.emptyText;
    return <>{typeof empty === 'function' ? empty() : (empty ?? <EmptyState title="No results" />)}</>;
  }
  return (
    <ul className="hp-cards">
      {rows.map((row, index) => (
        <CardRow<T>
          key={keyOf(row, index)}
          row={row}
          index={index}
          columns={columns}
          {...(props.expandable ? { expandable: props.expandable } : {})}
        />
      ))}
    </ul>
  );
}

export function DataTable<T extends object>({
  caption,
  columns,
  rows,
  rowKey,
  loading = false,
  fetching = false,
  error,
  onRetry,
  stale = false,
  emptyTitle = 'No results',
  emptyDescription,
  sort,
  onSortChange,
  filters,
  onFiltersChange,
  pagination,
  onRowClick,
  footer,
  expandable,
}: DataTableProps<T>) {
  const density = useDensity();
  // Phones get one card per row instead of a table that must be scrolled sideways.
  const narrow = useMediaQuery(NARROW_QUERY);

  const controlledColumns = useMemo(
    () =>
      columns.map((column) => {
        const key = columnKey(column);
        const next = { ...column };
        if (column.sorter && key !== undefined) {
          next.sortOrder = sort?.field === key ? sort.order : null;
        }
        if (column.filters && key !== undefined && filters) {
          next.filteredValue = (filters[key] as Key[] | null | undefined) ?? null;
        }
        return next;
      }),
    [columns, sort, filters],
  );

  const hasError = error !== undefined && error !== null;
  if (hasError && rows === undefined) {
    return <ErrorState error={error} {...(onRetry ? { onRetry } : {})} />;
  }

  const handleChange: TableProps<T>['onChange'] = (_pagination, tableFilters, sorter, extra) => {
    if (extra.action === 'sort' && onSortChange) {
      const s: SorterResult<T> | undefined = Array.isArray(sorter) ? sorter[0] : sorter;
      const field = s?.columnKey ?? (typeof s?.field === 'string' ? s.field : undefined);
      onSortChange(s?.order && field !== undefined ? { field: String(field), order: s.order } : null);
    }
    if (extra.action === 'filter' && onFiltersChange) {
      const next: FilterState = {};
      for (const [k, v] of Object.entries(tableFilters)) {
        next[k] = v ? v.map(String) : null;
      }
      onFiltersChange(next);
    }
  };

  return (
    <div role="region" aria-label={caption} aria-busy={loading || fetching}>
      {stale ? (
        <Alert
          className="hp-table-notice"
          type="warning"
          showIcon
          title="Live updates are unavailable; these rows may be out of date."
        />
      ) : null}
      {hasError ? (
        <Alert
          className="hp-table-notice"
          type="error"
          showIcon
          title="Refreshing failed; showing the last loaded data."
          action={
            onRetry ? (
              <Button size="small" onClick={onRetry}>
                Retry
              </Button>
            ) : undefined
          }
        />
      ) : null}
      {narrow ? (
        loading && rows === undefined ? (
          <div className="hp-cards__loading">
            <Spin />
          </div>
        ) : rows && rows.length > 0 ? (
          <ul className="hp-cards" aria-label={caption}>
            {rows.map((row, index) => (
              <CardRow<T>
                key={typeof rowKey === 'function' ? rowKey(row) : String(row[rowKey])}
                row={row}
                index={index}
                columns={columns}
                {...(onRowClick ? { onRowClick } : {})}
                {...(expandable ? { expandable } : {})}
              />
            ))}
          </ul>
        ) : (
          <EmptyState title={emptyTitle} description={emptyDescription} />
        )
      ) : (
        <Table<T>
          {...(expandable ? { expandable } : {})}
          columns={controlledColumns}
          dataSource={rows}
          rowKey={rowKey}
          loading={loading}
          size={density === 'compact' ? 'small' : 'middle'}
          pagination={false}
          onChange={handleChange}
          sortDirections={['ascend', 'descend']}
          showSorterTooltip={false}
          scroll={{ x: 'max-content' }}
          locale={{
            emptyText: loading ? ' ' : <EmptyState title={emptyTitle} description={emptyDescription} />,
          }}
          {...(onRowClick
            ? {
                onRow: (row: T) => ({
                  onClick: () => {
                    onRowClick(row);
                  },
                  style: { cursor: 'pointer' },
                }),
              }
            : {})}
        />
      )}
      {footer ? <div className="hp-table-note">{footer}</div> : null}
      {pagination ? (
        <nav className="hp-table-footer" aria-label={`${caption} pagination`}>
          {pagination.onPageSizeChange ? (
            <Select<number>
              aria-label="Rows per page"
              size="small"
              value={pagination.pageSize}
              onChange={pagination.onPageSizeChange}
              options={(pagination.pageSizeOptions ?? [25, 50, 100, 200]).map((n) => ({
                value: n,
                label: `${String(n)} / page`,
              }))}
              style={{ width: 120 }}
            />
          ) : null}
          <Button
            size="small"
            icon={<LeftOutlined />}
            disabled={!pagination.hasPreviousPage || loading}
            onClick={pagination.onPreviousPage}
          >
            Previous
          </Button>
          <Button
            size="small"
            disabled={!pagination.hasNextPage || loading}
            onClick={pagination.onNextPage}
            icon={<RightOutlined />}
            iconPlacement="end"
          >
            Next
          </Button>
        </nav>
      ) : null}
    </div>
  );
}
