import { App as AntApp, ConfigProvider, theme as antTheme } from 'antd';
import { createContext, useContext, useEffect, useMemo, type CSSProperties, type ReactNode } from 'react';

import { themeFor, type ResolvedTheme } from './tokens';

const ResolvedThemeContext = createContext<ResolvedTheme>('light');

/** Theme of the nearest ThemeProvider (the gallery renders light and dark side by side). */
export function useDsTheme(): ResolvedTheme {
  return useContext(ResolvedThemeContext);
}

/**
 * Exposes the resolved antd tokens as `--hp-*` custom properties for the static stylesheet
 * (src/ds/ds.css). Setting them through React's style prop uses the CSSOM, not inline <style> markup.
 */
function ThemeScope({
  mode,
  children,
  applyToDocument,
}: {
  mode: ResolvedTheme;
  children: ReactNode;
  applyToDocument: boolean;
}) {
  const { token } = antTheme.useToken();

  const vars = useMemo(
    () =>
      ({
        '--hp-color-text': token.colorText,
        '--hp-color-text-secondary': token.colorTextSecondary,
        '--hp-color-text-tertiary': token.colorTextTertiary,
        '--hp-color-primary': token.colorPrimary,
        '--hp-color-primary-bg': token.colorPrimaryBg,
        '--hp-color-success': token.colorSuccess,
        '--hp-color-warning': token.colorWarning,
        '--hp-color-error': token.colorError,
        '--hp-color-info': token.colorInfo,
        '--hp-color-warning-text': token.colorWarningText,
        '--hp-color-border': token.colorBorder,
        '--hp-color-border-secondary': token.colorBorderSecondary,
        '--hp-color-bg-container': token.colorBgContainer,
        '--hp-color-bg-layout': token.colorBgLayout,
        '--hp-color-fill-quaternary': token.colorFillQuaternary,
        '--hp-font-family': token.fontFamily,
        '--hp-font-family-code': token.fontFamilyCode,
        '--hp-radius': `${String(token.borderRadius)}px`,
        '--hp-radius-sm': `${String(token.borderRadiusSM)}px`,
        '--hp-radius-lg': `${String(token.borderRadiusLG)}px`,
        '--hp-focus-ring': token.colorPrimary,
      }) as CSSProperties,
    [token],
  );

  // Portaled overlays (modals, dropdowns) render outside the .hp-theme wrapper, so the root provider
  // also publishes the variables on <html>.
  useEffect(() => {
    if (!applyToDocument) {
      return;
    }
    const root = document.documentElement;
    root.dataset.theme = mode;
    root.style.colorScheme = mode;
    for (const [name, value] of Object.entries(vars as Record<string, string>)) {
      root.style.setProperty(name, value);
    }
    document.body.style.backgroundColor = token.colorBgLayout;
    document.body.style.color = token.colorText;
  }, [applyToDocument, mode, token, vars]);

  return (
    <div className="hp-theme" data-theme={mode} style={vars}>
      {children}
    </div>
  );
}

export interface ThemeProviderProps {
  mode: ResolvedTheme;
  children: ReactNode;
  /** Root provider only: sync `<html data-theme>`, color-scheme and body colors. */
  applyToDocument?: boolean;
}

export function ThemeProvider({ mode, children, applyToDocument = false }: ThemeProviderProps) {
  return (
    <ResolvedThemeContext value={mode}>
      <ConfigProvider theme={themeFor(mode)}>
        <AntApp component={false}>
          <ThemeScope mode={mode} applyToDocument={applyToDocument}>
            {children}
          </ThemeScope>
        </AntApp>
      </ConfigProvider>
    </ResolvedThemeContext>
  );
}
