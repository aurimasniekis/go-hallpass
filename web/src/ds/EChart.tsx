import { BarChart, LineChart } from 'echarts/charts';
import { DatasetComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import * as echarts from 'echarts/core';
import type { EChartsCoreOption } from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { useEffect, useRef } from 'react';

import { buildEchartsTheme, echartsThemeName } from './theme/echartsTheme';
import { useDsTheme } from './theme/ThemeProvider';

echarts.use([
  LineChart,
  BarChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  DatasetComponent,
  CanvasRenderer,
]);
echarts.registerTheme(echartsThemeName('light'), buildEchartsTheme('light'));
echarts.registerTheme(echartsThemeName('dark'), buildEchartsTheme('dark'));

export interface EChartProps {
  option: EChartsCoreOption;
  height?: number;
  /** Short accessible name for the chart image. */
  ariaLabel: string;
  /** ID of the element holding the textual summary. */
  describedBy?: string;
}

/**
 * Thin ECharts wrapper: tree-shaken modules, theme follows the app theme, resizes with its container,
 * disposes on unmount. The canvas is exposed as one image with an external summary; the data itself is
 * available through ChartCard's table view.
 */
export function EChart({ option, height = 240, ariaLabel, describedBy }: EChartProps) {
  const el = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);
  const mode = useDsTheme();

  useEffect(() => {
    const node = el.current;
    if (!node) {
      return;
    }
    const instance = echarts.init(node, echartsThemeName(mode), { renderer: 'canvas' });
    chart.current = instance;
    const observer = new ResizeObserver(() => {
      instance.resize();
    });
    observer.observe(node);
    return () => {
      observer.disconnect();
      instance.dispose();
      chart.current = null;
    };
  }, [mode]);

  useEffect(() => {
    chart.current?.setOption({ aria: { enabled: false }, ...option }, { notMerge: true });
  }, [option, mode]);

  return (
    <div
      ref={el}
      role="img"
      aria-label={ariaLabel}
      aria-describedby={describedBy}
      style={{ height, width: '100%' }}
    />
  );
}
