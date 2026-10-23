import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { revealControls, segmentUntrusted, truncateCodePoints } from './untrusted';
import { UntrustedText } from './UntrustedText';

describe('untrusted text helpers', () => {
  it('reveals bidi overrides, zero-width and C0/C1 controls', () => {
    expect(revealControls('ab\u202Ecd\u200Bef\u0007g\u009Bh')).toBe(
      'ab<U+202E>cd<U+200B>ef<U+0007>g<U+009B>h',
    );
  });

  it('keeps tabs, newlines and ordinary unicode', () => {
    expect(revealControls('line1\n\tline2 — ünïcödé 🙂')).toBe('line1\n\tline2 — ünïcödé 🙂');
    expect(segmentUntrusted('plain')).toEqual([{ kind: 'text', value: 'plain' }]);
  });

  it('truncates on code-point boundaries', () => {
    expect(truncateCodePoints('🙂🙂🙂', 2)).toEqual({ text: '🙂🙂', truncated: true });
    expect(truncateCodePoints('ab', 5)).toEqual({ text: 'ab', truncated: false });
  });
});

describe('<UntrustedText>', () => {
  it('renders HTML-looking input as inert text with an untrusted label', () => {
    const payload = '<img src=x onerror="alert(1)"><script>alert(2)</script>';
    const { container } = render(<UntrustedText text={payload} />);
    expect(screen.getByText('Untrusted')).toBeInTheDocument();
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    expect(container.textContent).toContain(payload);
  });

  it('marks hidden characters visibly', () => {
    const { container } = render(<UntrustedText text={'rm -rf /\u202E'} />);
    expect(container.querySelector('abbr')?.textContent).toBe('<U+202E>');
  });

  it('renders an em dash for empty input', () => {
    const { container } = render(<UntrustedText text={null} />);
    expect(container.textContent).toBe('—');
  });
});
