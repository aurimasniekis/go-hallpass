import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { Logo } from './Logo';

describe('<Logo>', () => {
  it('is decorative and uses a unique mask per instance', () => {
    render(
      <>
        <Logo />
        <Logo size={40} />
      </>,
    );
    const logos = screen.getAllByTestId('hp-logo');
    expect(logos).toHaveLength(2);
    expect(logos[0]).toHaveAttribute('aria-hidden', 'true');
    expect(logos[1]).toHaveAttribute('width', '40');
    const ids = logos.map((l) => l.querySelector('mask')?.id);
    expect(new Set(ids).size).toBe(2);
  });
});
