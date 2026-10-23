/**
 * Keyboard access for scrolling table bodies (WCAG 2.1.1; axe `scrollable-region-focusable`).
 *
 * Ant Design renders wide tables inside `.ant-table-content` / `.ant-table-body` with `overflow: auto`.
 * When such a container overflows and holds no focusable element, keyboard users cannot scroll it.
 * This makes exactly those containers focusable (tabindex 0) and names them; containers that stop
 * overflowing are restored.
 */
const SELECTOR = '.ant-table-content, .ant-table-body';
const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
const MARK = 'data-hp-scroll-focus';

function overflows(el: HTMLElement): boolean {
  return el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1;
}

function labelFor(el: HTMLElement): string {
  const region = el.closest('[role="region"][aria-label]');
  const name = region?.getAttribute('aria-label');
  return name ? `${name} (scrollable)` : 'Scrollable table';
}

/** Applies or removes the focusable marker on one container. Exported for tests. */
export function updateScrollable(el: HTMLElement): void {
  const marked = el.hasAttribute(MARK);
  const needs = overflows(el) && el.querySelector(FOCUSABLE) === null;
  if (needs && !marked) {
    el.setAttribute(MARK, '');
    el.tabIndex = 0;
    el.setAttribute('role', 'group');
    el.setAttribute('aria-label', labelFor(el));
  } else if (!needs && marked) {
    el.removeAttribute(MARK);
    el.removeAttribute('tabindex');
    el.removeAttribute('role');
    el.removeAttribute('aria-label');
  }
}

export function updateAllScrollable(root: ParentNode = document): void {
  root.querySelectorAll<HTMLElement>(SELECTOR).forEach(updateScrollable);
}

/** Watches the DOM and window size; returns a cleanup function. */
export function watchScrollableRegions(root: HTMLElement = document.body): () => void {
  let frame = 0;
  const schedule = () => {
    if (frame === 0) {
      frame = requestAnimationFrame(() => {
        frame = 0;
        updateAllScrollable(root);
      });
    }
  };
  const observer = new MutationObserver(schedule);
  observer.observe(root, { childList: true, subtree: true });
  window.addEventListener('resize', schedule);
  schedule();
  return () => {
    observer.disconnect();
    window.removeEventListener('resize', schedule);
    if (frame !== 0) {
      cancelAnimationFrame(frame);
    }
  };
}
