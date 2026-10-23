import { LeftOutlined, RightOutlined } from '@ant-design/icons';
import { Alert, Button, Select, Table, type TableColumnsType, type TableProps } from 'antd';
import type { SorterResult } from 'antd/es/table/interface';
import { useMemo, type Key, type ReactNode } from 'react';

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
}: DataTableProps<T>) {
  const density = useDensity();

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
      <Table<T>
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
