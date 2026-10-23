// Post-build checks for the production bundle (docs/PLAN.md §12.3 CSP, §14.1 dev-only tooling).
// Fails the build when:
//   - index.html contains inline scripts or inline event handlers (CSP is `script-src 'self'`);
//   - dev-only code (TanStack devtools, the /__ds gallery) leaked into the bundle.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const dist = new URL('../dist/', import.meta.url).pathname;
const failures = [];

const html = readFileSync(join(dist, 'index.html'), 'utf8');
for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
  const attrs = match[1] ?? '';
  const body = (match[2] ?? '').trim();
  if (!/\bsrc\s*=/.test(attrs) || body !== '') {
    failures.push(`index.html: inline <script> is not allowed by CSP: ${match[0].slice(0, 120)}`);
  }
}
if (/\son[a-z]+\s*=/i.test(html)) {
  failures.push('index.html: inline event handler attribute found');
}
if (/javascript:/i.test(html)) {
  failures.push('index.html: javascript: URL found');
}

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

// Strings that only exist in dev-only modules.
const forbidden = [
  ['Design system gallery', '/__ds gallery'],
  ['TanStack Query', 'TanStack devtools plugin list'],
  ['tsqd-', 'TanStack Query devtools'],
  ['TanStackRouterDevtools', 'TanStack Router devtools'],
];
const assets = walk(dist).filter((p) => p.endsWith('.js') || p.endsWith('.css'));
for (const file of assets) {
  const text = readFileSync(file, 'utf8');
  for (const [needle, what] of forbidden) {
    if (text.includes(needle)) {
      failures.push(`${file.slice(dist.length)}: contains ${what} (${JSON.stringify(needle)})`);
    }
  }
}

// CSP permits data: URIs only for images; fonts or scripts inlined as data: would be blocked at runtime.
for (const file of assets.filter((p) => p.endsWith('.css'))) {
  const text = readFileSync(file, 'utf8');
  if (/url\(\s*["']?data:(?!image\/)/i.test(text)) {
    failures.push(`${file.slice(dist.length)}: non-image data: URI in CSS is blocked by the CSP`);
  }
}

if (failures.length > 0) {
  console.error('check-dist: FAILED');
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`check-dist: OK (${assets.length} assets; no inline scripts; no dev-only modules)`);
