/**
 * WCAG 2.x contrast helpers used by the token contrast test (HP-UI-002, HP-UI-014).
 * Supports #rgb, #rrggbb, #rrggbbaa and rgb()/rgba() inputs; translucent foregrounds are composited
 * over the (opaque) background before measuring, which is how the browser renders them.
 */

export interface Rgba {
  r: number;
  g: number;
  b: number;
  a: number;
}

export function parseColor(input: string): Rgba {
  const value = input.trim().toLowerCase();
  const hex = /^#([0-9a-f]{3,8})$/.exec(value);
  if (hex?.[1] !== undefined) {
    const h = hex[1];
    if (h.length === 3 || h.length === 4) {
      const [r, g, b, a] = Array.from({ length: h.length }, (_, i) => parseInt(h.charAt(i).repeat(2), 16));
      return { r: r ?? 0, g: g ?? 0, b: b ?? 0, a: a === undefined ? 1 : a / 255 };
    }
    if (h.length === 6 || h.length === 8) {
      const n = (i: number) => parseInt(h.slice(i, i + 2), 16);
      return { r: n(0), g: n(2), b: n(4), a: h.length === 8 ? n(6) / 255 : 1 };
    }
  }
  const fn = /^rgba?\(([^)]+)\)$/.exec(value);
  if (fn?.[1] !== undefined) {
    const parts = fn[1].split(/[\s,/]+/).filter(Boolean);
    const [r, g, b, a] = parts.map((p) => (p.endsWith('%') ? (parseFloat(p) / 100) * 255 : parseFloat(p)));
    if (r !== undefined && g !== undefined && b !== undefined) {
      const alpha = parts[3]?.endsWith('%') ? parseFloat(parts[3]) / 100 : (a ?? 1);
      return { r, g, b, a: alpha };
    }
  }
  throw new Error(`Unsupported color: ${input}`);
}

/** Composites `fg` over an opaque `bg` (source-over). */
export function composite(fg: Rgba, bg: Rgba): Rgba {
  const a = fg.a;
  return {
    r: fg.r * a + bg.r * (1 - a),
    g: fg.g * a + bg.g * (1 - a),
    b: fg.b * a + bg.b * (1 - a),
    a: 1,
  };
}

function channel(c: number): number {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

export function relativeLuminance(c: Rgba): number {
  return 0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b);
}

/** WCAG contrast ratio of `foreground` rendered on `background` (background must be opaque). */
export function contrastRatio(foreground: string, background: string): number {
  const bg = parseColor(background);
  if (bg.a < 1) {
    throw new Error(`Background must be opaque: ${background}`);
  }
  const fg = composite(parseColor(foreground), bg);
  const l1 = relativeLuminance(fg);
  const l2 = relativeLuminance(bg);
  const [hi, lo] = l1 > l2 ? [l1, l2] : [l2, l1];
  return (hi + 0.05) / (lo + 0.05);
}
