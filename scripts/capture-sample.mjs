// Record a real run with the bundled fictional prompt, for the page's "Check a recorded run" button.
// Usage: NEARAI_KEY=sk-... node scripts/capture-sample.mjs [--aggressive | --extreme] [out.json]
import { writeFileSync } from 'node:fs';
import { runLab, verifyReceipt } from '../web/engine.js';
import { SAMPLE_PROMPT, SAMPLE_TESTS } from '../web/sample.js';
import { nodeDeps } from './deps.mjs';

const key = process.env.NEARAI_KEY;
if (!key) { console.error('Set NEARAI_KEY (get one at https://cloud.near.ai).'); process.exit(1); }
const mode = process.argv.includes('--extreme') ? 'extreme' : process.argv.includes('--aggressive') ? 'aggressive' : 'careful';
const out = process.argv.slice(2).find((a) => !a.startsWith('--')) || (mode === 'careful' ? 'web/sample-run.json' : `web/sample-${mode}.json`);
const rc = await runLab({ key, mode, prompt: SAMPLE_PROMPT, tests: SAMPLE_TESTS, onStep: (_, m) => console.log('·', m) }, nodeDeps);
const v = await verifyReceipt(rc, nodeDeps);
writeFileSync(out, JSON.stringify(rc));
console.log(`\n${v.ok ? 'VERIFIED' : 'NOT VERIFIED'}  ${v.safe ? 'SAFE TO ADOPT' : `REGRESSIONS ${v.regressions.length}`}  tokens ${v.tokens.original} -> ${v.tokens.optimized}  saved/call ${v.tokens.savedPerCall}`);
for (const t of v.tests) console.log(`  test: original ${t.original.pass ? 'pass' : 'FAIL ' + t.original.fails}  optimized ${t.optimized.pass ? 'pass' : 'FAIL ' + t.optimized.fails}`);
console.log(`wrote ${out}`);
