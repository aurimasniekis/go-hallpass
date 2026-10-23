import { palettes, type ResolvedTheme } from './tokens';

/**
 * ECharts themes derived from the design tokens (HP-UI-009: theme-aware charts).
 * Categorical series colors follow a fixed order validated for color-vision deficiency in both modes
 * (dataviz reference palette). Several light-mode slots are below 3:1 against the surface, so every
 * chart must keep its "View as table" alternative (ChartCard enforces this).
 */
export const CATEGORICAL: Record<ResolvedTheme, readonly string[]> = {
  light: ['#2a78d6', '#eb6834', '#1baf7a', '#eda100', '#e87ba4', '#008300', '#6250d6', '#e34948'],
  dark: ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#008300', '#9085e9', '#e66767'],
};

export function echartsThemeName(mode: ResolvedTheme): string {
  return `hallpass-${mode}`;
}

export function buildEchartsTheme(mode: ResolvedTheme): Record<string, unknown> {
  const p = palettes[mode];
  const axis = {
    axisLine: { show: true, lineStyle: { color: p.border } },
    axisTick: { show: false },
    axisLabel: { color: p.textSecondary },
    splitLine: { show: true, lineStyle: { color: p.borderSecondary, width: 1 } },
    nameTextStyle: { color: p.textSecondary },
  };
  return {
    color: [...CATEGORICAL[mode]],
    backgroundColor: 'transparent',
    textStyle: { color: p.text, fontFamily: 'inherit' },
    title: { textStyle: { color: p.text }, subtextStyle: { color: p.textSecondary } },
    legend: { textStyle: { color: p.textSecondary }, icon: 'roundRect', itemWidth: 12, itemHeight: 8 },
    tooltip: {
      backgroundColor: p.bgElevated,
      borderColor: p.border,
      borderWidth: 1,
      textStyle: { color: p.text },
      extraCssText: 'box-shadow: none; border-radius: 4px;',
    },
    categoryAxis: { ...axis, splitLine: { show: false } },
    valueAxis: { ...axis, axisLine: { show: false } },
    timeAxis: { ...axis, splitLine: { show: false } },
    line: { symbol: 'circle', symbolSize: 6, showSymbol: false, lineStyle: { width: 2 } },
    bar: { itemStyle: { borderRadius: [4, 4, 0, 0] }, barMaxWidth: 24 },
  };
}
