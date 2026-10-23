import { describe, expect, it } from 'vitest';

import { updateScrollable } from './scrollableRegions';

function container(overflow: boolean, withButton = false): HTMLElement {
  const region = document.createElement('div');
  region.setAttribute('role', 'region');
  region.setAttribute('aria-label', 'Agent keys');
  const el = document.createElement('div');
  el.className = 'ant-table-content';
  el.append(document.createElement(withButton ? 'button' : 'span'));
  Object.defineProperty(el, 'scrollWidth', { configurable: true, get: () => (overflow ? 800 : 300) });
  Object.defineProperty(el, 'clientWidth', { configurable: true, get: () => 300 });
  region.append(el);
  return el;
}

describe('scrollable table regions', () => {
  it('makes an overflowing container without focusable content keyboard-reachable and named', () => {
    const el = container(true);
    updateScrollable(el);
    expect(el.tabIndex).toBe(0);
    expect(el.getAttribute('role')).toBe('group');
    expect(el.getAttribute('aria-label')).toBe('Agent keys (scrollable)');
  });

  it('leaves containers alone that do not overflow or already contain focusable elements', () => {
    const narrow = container(false);
    updateScrollable(narrow);
    expect(narrow.hasAttribute('tabindex')).toBe(false);
    const withButton = container(true, true);
    updateScrollable(withButton);
    expect(withButton.hasAttribute('tabindex')).toBe(false);
  });

  it('removes its marker when the container stops overflowing', () => {
    const el = container(true);
    updateScrollable(el);
    Object.defineProperty(el, 'scrollWidth', { configurable: true, get: () => 300 });
    updateScrollable(el);
    expect(el.hasAttribute('tabindex')).toBe(false);
    expect(el.hasAttribute('role')).toBe(false);
  });
});
