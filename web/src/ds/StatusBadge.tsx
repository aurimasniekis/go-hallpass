import type { ReactNode } from 'react';

export type StatusTone = 'neutral' | 'success' | 'warning' | 'error' | 'info' | 'processing';

export interface StatusBadgeProps {
  tone: StatusTone;
  children: ReactNode;
}

/**
 * Restrained status indicator: a small square marker plus neutral text. The label always carries the
 * meaning, so status is never conveyed by color alone (WCAG 1.4.1).
 */
export function StatusBadge({ tone, children }: StatusBadgeProps) {
  return (
    <span className={`hp-status hp-status--${tone}`}>
      <span className="hp-status__dot" aria-hidden="true" />
      <span>{children}</span>
    </span>
  );
}
