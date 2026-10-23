import { theme } from 'antd';
import { describe, expect, it } from 'vitest';

import { contrastRatio, parseColor } from './contrast';
import { darkTheme, lightTheme, palettes, type ResolvedTheme } from './tokens';

const AA_TEXT = 4.5;

describe('contrastRatio', () => {
  it('matches known WCAG reference values', () => {
    expect(contrastRatio('#000000', '#ffffff')).toBeCloseTo(21, 5);
    expect(contrastRatio('#ffffff', '#ffffff')).toBeCloseTo(1, 5);
    expect(contrastRatio('#767676', '#ffffff')).toBeGreaterThanOrEqual(4.5);
    expect(contrastRatio('#777777', '#ffffff')).toBeLessThan(4.5);
  });

  it('composites translucent foregrounds over the background', () => {
    expect(parseColor('rgba(0, 0, 0, 0.5)').a).toBe(0.5);
    expect(contrastRatio('rgba(0,0,0,0)', '#ffffff')).toBeCloseTo(1, 5);
    expect(contrastRatio('rgba(0,0,0,0.88)', '#ffffff')).toBeGreaterThan(12);
  });
});

/** Text tokens that must reach 4.5:1 on every surface. Disabled text is exempt per WCAG 1.4.3. */
const TEXT_TOKENS = [
  'colorText',
  'colorTextHeading',
  'colorTextLabel',
  'colorTextSecondary',
  'colorTextTertiary',
  'colorTextDescription',
  'colorTextPlaceholder',
  'colorLink',
  'colorLinkHover',
  'colorPrimaryText',
  'colorSuccessText',
  'colorWarningText',
  'colorErrorText',
  'colorInfoText',
  // antd also uses the base semantic colors as text (Typography types, Tabs, default danger buttons,
  // Spin description, Pagination), so they must pass too.
  'colorPrimary',
  'colorError',
  'colorSuccess',
  'colorWarning',
  'colorInfo',
] as const;

const SURFACE_TOKENS = ['colorBgContainer', 'colorBgLayout', 'colorBgElevated'] as const;

const themes: Record<ResolvedTheme, typeof lightTheme> = { light: lightTheme, dark: darkTheme };

describe.each(Object.entries(themes) as [ResolvedTheme, typeof lightTheme][])(
  '%s theme tokens',
  (name, config) => {
    const token = theme.getDesignToken(config) as unknown as Record<string, unknown>;
    const color = (key: string): string => {
      const value = token[key];
      if (typeof value !== 'string') {
        throw new Error(`token ${key} is not a color string`);
      }
      return value;
    };

    const pairs = TEXT_TOKENS.flatMap((fg) => SURFACE_TOKENS.map((bg) => [fg, bg] as const));
    it.each(pairs)('%s on %s meets WCAG AA', (fg, bg) => {
      expect(contrastRatio(color(fg), color(bg))).toBeGreaterThanOrEqual(AA_TEXT);
    });

    it.each([
      'colorPrimary',
      'colorPrimaryHover',
      'colorPrimaryActive',
      'colorError',
      'colorErrorHover',
      'colorErrorActive',
    ] as const)('text on solid %s controls meets WCAG AA', (bg) => {
      expect(contrastRatio(color('colorTextLightSolid'), color(bg))).toBeGreaterThanOrEqual(AA_TEXT);
    });

    it('checkbox/switch white marks on primary meet the 3:1 non-text minimum', () => {
      expect(contrastRatio(color('colorWhite'), color('colorPrimary'))).toBeGreaterThanOrEqual(3);
    });

    it('selected navigation item text meets WCAG AA on its highlight', () => {
      expect(contrastRatio(color('colorPrimaryText'), color('colorPrimaryBg'))).toBeGreaterThanOrEqual(
        AA_TEXT,
      );
    });

    it('semantic status text meets WCAG AA on the subtle surface used by tables', () => {
      const subtle = palettes[name].bgSubtle;
      for (const fg of [
        'colorText',
        'colorTextSecondary',
        'colorSuccessText',
        'colorWarningText',
        'colorErrorText',
      ]) {
        expect(contrastRatio(color(fg), subtle), fg).toBeGreaterThanOrEqual(AA_TEXT);
      }
    });

    it('uses restrained radii (no pills)', () => {
      expect(token.borderRadius).toBe(4);
      expect(token.borderRadiusLG).toBe(6);
      expect(token.borderRadiusSM).toBe(2);
      expect(token.controlHeight).toBe(32);
    });
  },
);
