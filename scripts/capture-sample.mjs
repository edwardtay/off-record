// Record a real private question with the bundled fictional message, for the page's demo.
// Usage: NEARAI_KEY=sk-... node scripts/capture-sample.mjs [out.json]
import { writeFileSync } from 'node:fs';
import { runAsk, verifyReceipt } from '../web/engine.js';
import { SAMPLE_ASK } from '../web/sample.js';
import { nodeDeps } from './deps.mjs';

const key = process.env.NEARAI_KEY;
if (!key) { console.error('Set NEARAI_KEY (get one at https://cloud.near.ai).'); process.exit(1); }
const out = process.argv[2] || 'web/sample-ask.json';
const rc = await runAsk({ key, ...SAMPLE_ASK, onStep: (_, m) => console.log('·', m) }, nodeDeps);
const v = await verifyReceipt(rc, nodeDeps);
writeFileSync(out, JSON.stringify(rc));
console.log(`\n${v.ok ? 'VERIFIED' : 'NOT VERIFIED'}  ${(v.sensitive || []).length} sensitive items found inside the enclave\nwrote ${out}`);
