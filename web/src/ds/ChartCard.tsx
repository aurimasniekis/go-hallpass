import { Button, Card, Table } from 'antd';
import type { EChartsCoreOption } from 'echarts/core';
import { lazy, Suspense, useId, useState, type ReactNode } from 'react';

import { EmptyState, ErrorState, LoadingState } from './states';

const EChart = lazy(() => import('./EChart').then((m) => ({ default: m.EChart })));

export interface ChartTableColumn {
  key: string;
  title: string;
}

export interface ChartCardProps {
  title: string;
  /**
   * Plain-language summary of what the chart shows (trend, latest value, range). Linked with
   * aria-describedby and shown under the title (HP-UI-009).
   */
  summary: string;
  option: EChartsCoreOption;
  /** Same data as the chart, for the "View as table" alternative. */
  table: { columns: readonly ChartTableColumn[]; rows: readonly Record<string, ReactNode>[] };
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  /** The endpoint returned no data points. */
  empty?: boolean;
  height?: number;
  extra?: ReactNode;
}

/**
 * Chart container with an accessible summary and a table alternative. Charts must only be fed by real
 * metrics endpoints; there is no demo-data mode.
 */
export function ChartCard({
  title,
  summary,
  option,
  table,
  loading,
  error,
  onRetry,
  empty,
  height = 240,
  extra,
}: ChartCardProps) {
  const [asTable, setAsTable] = useState(false);
  const summaryId = useId();

  let body: ReactNode;
  if (loading) {
    body = <LoadingState label={`Loading ${title.toLowerCase()}…`} />;
  } else if (error !== undefined && error !== null) {
    body = <ErrorState error={error} {...(onRetry ? { onRetry } : {})} />;
  } else if (empty) {
    body = <EmptyState title="No data for this period" />;
  } else if (asTable) {
    body = (
      <Table
        size="small"
        pagination={false}
        rowKey={(_row, index) => String(index)}
        columns={table.columns.map((c) => ({ key: c.key, dataIndex: c.key, title: c.title }))}
        dataSource={table.rows as Record<string, ReactNode>[]}
        scroll={{ y: height }}
      />
    );
  } else {
    body = (
      <Suspense fallback={<LoadingState label="Loading chart…" />}>
        <EChart option={option} height={height} ariaLabel={title} describedBy={summaryId} />
      </Suspense>
    );
  }

  const ready = !loading && (error === undefined || error === null) && !empty;
  return (
    <Card
      title={title}
      size="small"
      extra={
        <>
          {extra}
          <Button
            size="small"
            type="text"
            aria-pressed={asTable}
            disabled={!ready}
            onClick={() => {
              setAsTable((v) => !v);
            }}
          >
            {asTable ? 'View as chart' : 'View as table'}
          </Button>
        </>
      }
    >
      <p id={summaryId} className="hp-chart-summary">
        {summary}
      </p>
      {body}
    </Card>
  );
}
