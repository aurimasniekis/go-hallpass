import { useId } from 'react';

/**
 * The HallPass mark: a pass with an "H" cut out. Decorative (hidden from assistive technology); the product name
 * next to it carries the meaning. Inline so it needs no extra request and works under the CSP.
 */
export function Logo({ size = 24, className }: { size?: number; className?: string }) {
  const mask = `hp-logo-${useId().replace(/:/g, '')}`;
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 64 64"
      aria-hidden="true"
      focusable="false"
      data-testid="hp-logo"
    >
      <defs>
        <mask id={mask}>
          <rect width="64" height="64" fill="#fff" />
          <circle cx="4" cy="32" r="7" fill="#000" />
          <circle cx="60" cy="32" r="7" fill="#000" />
          <path
            d="M22 22v20M42 22v20M22 32h20"
            stroke="#000"
            strokeWidth="5"
            strokeLinecap="round"
            fill="none"
          />
        </mask>
      </defs>
      <rect x="4" y="12" width="56" height="40" rx="8" fill="#2f63d1" mask={`url(#${mask})`} />
    </svg>
  );
}
