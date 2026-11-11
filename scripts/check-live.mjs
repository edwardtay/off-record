// Does the page prompt20.com serves match this repository? Fetches every file under web/ from the live
// site and compares its SHA-256 with the file in this checkout. Run it at the commit you want to check.
// Usage: node scripts/check-live.mjs [base-url]
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative } from 'node:path';

const BASE = (process.argv[2] || 'https://prompt20.com/tools/off-record/').replace(/\/?$/, '/');
const ROOT = new URL('../web/', import.meta.url).pathname;
const sha = (b) => createHash('sha256').update(b).digest('hex');
const walk = (d) => readdirSync(d).flatMap((f) => (statSync(join(d, f)).isDirectory() ? walk(join(d, f)) : [join(d, f)]));

let bad = 0; let gone = 0;
for (const file of walk(ROOT).sort()) {
  const path = relative(ROOT, file);
  const local = sha(readFileSync(file));
  let live = 'unreachable';
  try {
    const r = await fetch(BASE + path, { headers: { 'cache-control': 'no-cache' } });
    live = r.ok ? sha(Buffer.from(await r.arrayBuffer())) : `HTTP ${r.status}`;
  } catch { /* stays unreachable */ }
  const ok = live === local;
  if (!ok && /^(unreachable|HTTP )/.test(live)) gone++; else if (!ok) bad++;
  console.log(`${ok ? 'MATCH   ' : /^(unreachable|HTTP )/.test(live) ? 'NO FILE ' : 'DIFFERS '} ${local.slice(0, 16)}  ${path}${ok ? '' : `  (live: ${live.slice(0, 16)})`}`);
}
console.log(bad ? `\n${bad} file(s) differ from this checkout.` : gone ? `\n${gone} file(s) could not be fetched; nothing compared differs.` : `\nEvery file of this page in web/ is served at ${BASE} exactly as in this checkout.`);
process.exit(bad || gone ? 1 : 0);
