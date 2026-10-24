import { theme, type ThemeConfig } from 'antd';

/**
 * HallPass design tokens (docs/PLAN.md §14.2, HP-UI-002).
 *
 * - Radius 4 (cards and overlays 6, small elements 2). No pill shapes, no gradients.
 * - controlHeight 32; compact tables use 28 px rows.
 * - Neutral grays, one blue brand accent, semantic success/warning/error/info.
 * - 1px subtle borders; shadow only on overlays.
 * - Text colors are explicit solid values so that WCAG AA (4.5:1) can be verified by
 *   `contrast.test.ts` against every surface background in both themes.
 */

export type ResolvedTheme = 'light' | 'dark';

export const fontFamily =
  "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, 'Noto Sans', sans-serif";
export const fontFamilyCode =
  "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace";

/** Palette per theme. Only these values are used for text, surfaces and semantics. */
export const palettes = {
  light: {
    primary: '#2458b3',
    link: '#2458b3',
    linkHover: '#1b4690',
    success: '#237a3b',
    warning: '#a35607',
    error: '#c0352b',
    info: '#2458b3',
    successText: '#1d6631',
    warningText: '#8a4a08',
    errorText: '#a92d24',
    infoText: '#1f4f9f',
    text: '#1d2129',
    textSecondary: '#454c57',
    textTertiary: '#5b6370',
    textPlaceholder: '#666e7a',
    bgLayout: '#f4f5f7',
    bgContainer: '#ffffff',
    bgElevated: '#ffffff',
    bgSubtle: '#f7f8fa',
    border: '#d3d7de',
    borderSecondary: '#e5e8ec',
    primaryBg: '#e8eef9',
  },
  dark: {
    // Dark seeds are lighter than their light counterparts because theme.darkAlgorithm darkens seeds
    // (e.g. #7aa6f5 → #6b90d3). antd does not let seed tokens be overridden after derivation, so the
    // seeds are chosen such that the *derived* colors pass WCAG AA as text (see contrast.test.ts).
    primary: '#7aa6f5',
    link: '#82abf5',
    linkHover: '#a6c3f8',
    success: '#5cc27b',
    warning: '#e2a24c',
    error: '#f6847a',
    info: '#7aa6f5',
    successText: '#73c48a',
    warningText: '#e1a75e',
    errorText: '#f08b82',
    infoText: '#8fb3f3',
    text: '#e4e7ec',
    textSecondary: '#b6bcc6',
    textTertiary: '#9ea5b0',
    textPlaceholder: '#8e96a1',
    bgLayout: '#0f1115',
    bgContainer: '#171a1f',
    bgElevated: '#1e2228',
    bgSubtle: '#1b1e24',
    border: '#3a4049',
    borderSecondary: '#2a2f36',
    primaryBg: '#1b2a44',
  },
} as const;

export type Palette = (typeof palettes)[ResolvedTheme];

function buildTheme(mode: ResolvedTheme): ThemeConfig {
  const p = palettes[mode];
  const overlayShadow =
    mode === 'light' ? '0 2px 8px rgba(15, 23, 42, 0.12)' : '0 2px 8px rgba(0, 0, 0, 0.45)';
  return {
    algorithm: mode === 'dark' ? theme.darkAlgorithm : theme.defaultAlgorithm,
    hashed: true,
    cssVar: { key: `hp-${mode}` },
    token: {
      // Seeds
      colorPrimary: p.primary,
      colorInfo: p.info,
      colorSuccess: p.success,
      colorWarning: p.warning,
      colorError: p.error,
      colorLink: p.link,
      colorTextBase: p.text,
      colorBgBase: p.bgContainer,
      borderRadius: 4,
      controlHeight: 32,
      fontFamily,
      fontFamilyCode,
      fontSize: 14,
      wireframe: false,
      motion: true,
      // Map/alias overrides (explicit, so contrast is verifiable)
      borderRadiusLG: 6,
      borderRadiusSM: 2,
      borderRadiusXS: 2,
      borderRadiusOuter: 4,
      colorText: p.text,
      colorTextHeading: p.text,
      colorTextLabel: p.textSecondary,
      colorTextSecondary: p.textSecondary,
      colorTextDescription: p.textTertiary,
      colorTextTertiary: p.textTertiary,
      colorTextPlaceholder: p.textPlaceholder,
      colorIcon: p.textTertiary,
      colorIconHover: p.text,
      colorLinkHover: p.linkHover,
      colorLinkActive: p.linkHover,
      colorPrimaryText: mode === 'light' ? p.primary : p.link,
      colorPrimaryTextHover: p.linkHover,
      colorSuccessText: p.successText,
      colorWarningText: p.warningText,
      colorErrorText: p.errorText,
      colorInfoText: p.infoText,
      colorBgLayout: p.bgLayout,
      colorBgContainer: p.bgContainer,
      colorBgElevated: p.bgElevated,
      colorBorder: p.border,
      colorBorderSecondary: p.borderSecondary,
      colorSplit: p.borderSecondary,
      colorPrimaryBg: p.primaryBg,
      // Text on solid primary/danger controls: white in light mode, dark ink in dark mode (the derived
      // dark primary/error colors are too light for white text at 4.5:1).
      colorTextLightSolid: mode === 'light' ? '#ffffff' : p.bgLayout,
      ...(mode === 'dark'
        ? { colorPrimaryActive: '#5f86cc', colorErrorActive: '#cf6a61' }
        : { colorErrorHover: '#a92d24' }),
      boxShadow: overlayShadow,
      boxShadowSecondary: overlayShadow,
      boxShadowTertiary: 'none',
    },
    components: {
      Layout: {
        headerBg: p.bgContainer,
        siderBg: p.bgContainer,
        bodyBg: p.bgLayout,
        headerHeight: 48,
        headerPadding: '0 16px',
      },
      Card: { borderRadiusLG: 6, boxShadowTertiary: 'none' },
      Modal: { borderRadiusLG: 6 },
      Button: { primaryShadow: 'none', defaultShadow: 'none', dangerShadow: 'none', fontWeight: 500 },
      Table: {
        cellPaddingBlock: 8,
        cellPaddingInline: 12,
        cellPaddingBlockSM: 3,
        cellPaddingInlineSM: 8,
        headerBg: p.bgSubtle,
        headerColor: p.textSecondary,
        headerBorderRadius: 4,
        rowHoverBg: p.bgSubtle,
      },
      Menu: {
        itemBorderRadius: 4,
        itemHeight: 32,
        itemMarginBlock: 2,
        itemBg: 'transparent',
        itemColor: p.textSecondary,
        itemHoverColor: p.text,
        itemSelectedColor: mode === 'light' ? p.primary : p.link,
        itemSelectedBg: p.primaryBg,
        groupTitleColor: p.textTertiary,
        subMenuItemBg: 'transparent',
        activeBarBorderWidth: 0,
      },
      Tag: { borderRadiusSM: 2, defaultBg: p.bgSubtle, defaultColor: p.textSecondary },
      Segmented: { borderRadius: 4, borderRadiusSM: 2, borderRadiusXS: 2, borderRadiusLG: 4 },
      Tooltip: { borderRadius: 4 },
      Alert: { borderRadiusLG: 4 },
    },
  };
}

export const lightTheme: ThemeConfig = buildTheme('light');
export const darkTheme: ThemeConfig = buildTheme('dark');

export function themeFor(mode: ResolvedTheme): ThemeConfig {
  return mode === 'dark' ? darkTheme : lightTheme;
}
