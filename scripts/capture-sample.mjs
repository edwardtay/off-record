// Record a real two-turn private chat with the bundled fictional patient, for the page's demo.
// Usage: NEARAI_KEY=sk-... node scripts/capture-sample.mjs [out.json]
import { writeFileSync } from 'node:fs';
import { openSession, newReceipt, sendTurn, verifyReceipt } from '../web/engine.js';
import { SAMPLE_ASK, SAMPLE_FOLLOWUP } from '../web/sample.js';
import { nodeDeps } from './deps.mjs';

const key = process.env.NEARAI_KEY;
if (!key) { console.error('Set NEARAI_KEY (get one at https://cloud.near.ai).'); process.exit(1); }
const out = process.argv[2] || 'web/sample-chat.json';
const session = await openSession({ onStep: (_, m) => console.log('·', m) }, nodeDeps);
const rc = newReceipt(session, SAMPLE_ASK.system);
const replies = [];
for (const message of [SAMPLE_ASK.message, SAMPLE_FOLLOWUP]) {
  let text = '';
  await sendTurn({ key, session, rc, replies, message, onDelta: (d) => { text += d; } }, nodeDeps);
  replies.push(text.trim());
  console.log(`· turn ${rc.turns.length}: ${text.length} characters streamed`);
}
const v = await verifyReceipt(rc, nodeDeps);
writeFileSync(out, JSON.stringify(rc));
console.log(`\n${v.ok ? 'VERIFIED' : 'NOT VERIFIED'}  ${rc.turns.length} turns, ${(v.sensitive || []).length} sensitive items found inside the enclave\nwrote ${out}`);
if (!v.ok) for (const r of [...v.att.rows, ...v.structure]) if (!r.ok) console.log('FAIL', r.label, r.detail);
