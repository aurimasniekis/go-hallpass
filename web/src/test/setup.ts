import '@testing-library/jest-dom/vitest';

import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

afterEach(() => {
  cleanup();
});

// jsdom lacks matchMedia and ResizeObserver, which Ant Design and the theme store use.
if (typeof window !== 'undefined') {
  if (!('matchMedia' in window) || typeof window.matchMedia !== 'function') {
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      configurable: true,
      value: vi.fn((query: string) => ({
        matches: false,
        media: query,
        onchange: null,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        addListener: vi.fn(),
        removeListener: vi.fn(),
        dispatchEvent: vi.fn(() => false),
      })),
    });
  }
  if (!('ResizeObserver' in window)) {
    class ResizeObserverStub {
      observe(): void {
        // no-op
      }
      unobserve(): void {
        // no-op
      }
      disconnect(): void {
        // no-op
      }
    }
    Object.defineProperty(window, 'ResizeObserver', {
      writable: true,
      configurable: true,
      value: ResizeObserverStub,
    });
  }
}
