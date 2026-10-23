import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';

export const WCAG_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

/** Fails on serious or critical axe violations (HP-UI-014), with the violation list as the message. */
export async function expectNoSeriousViolations(page: Page, soft = false): Promise<void> {
  // Finish CSS transitions first: antd animates colors (e.g. a button turning enabled), and a mid-transition
  // color is a false contrast failure. This only affects the audit, not the page under test.
  await page.addStyleTag({
    content: '*,*::before,*::after{transition:none!important;animation:none!important}',
  });
  await page.waitForTimeout(50);
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  const blocking = results.violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => ({
      id: v.id,
      impact: v.impact,
      help: v.help,
      targets: v.nodes.map((n) => n.target.join(' ')),
    }));
  (soft ? expect.soft : expect)(blocking, `${page.url()}\n${JSON.stringify(blocking, null, 2)}`).toEqual([]);
}
