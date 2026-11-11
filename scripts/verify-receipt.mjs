// Check a Private Prompt Lab receipt from scratch, no API key needed.
// Usage: node scripts/verify-receipt.mjs web/sample-run.json [--tamper | --swap-test] [--offline]
//   Intel's and NVIDIA's verifiers and NEAR AI's live attestation are always asked now.
//   --tamper     flip one byte in the optimiser's reply first, to watch the check fail
//   --swap-test  rewrite a test message in the receipt, to watch the check fail
//   --offline    skip the network checks (the verdict is then never VERIFIED)
import { readFileSync } from 'node:fs';
import { verifyReceipt } from '../web/engine.js';
import { nodeDeps } from './deps.mjs';

const file = process.argv[2] || 'web/sample-run.json';
const rc = JSON.parse(readFileSync(file, 'utf8'));
if (process.argv.includes('--tamper')) {
  const c = rc.calls.find((x) => x.role === 'optimize');
  const i = c.response.indexOf('"content"') + 12;
  c.response = c.response.slice(0, i) + (c.response[i] === 'a' ? 'b' : 'a') + c.response.slice(i + 1);
  console.log('Tampered: flipped one byte in the optimiser reply.\n');
}
if (process.argv.includes('--swap-test')) {
  rc.tests[0].input = 'A different message than the one the model answered';
  console.log('Tampered: rewrote test 1 message in the receipt.\n');
}
const v = await verifyReceipt(rc, nodeDeps, { offline: process.argv.includes('--offline') });
const mark = (ok) => (ok ? 'PASS' : 'FAIL');
console.log(`Receipt ${file}\nmodel ${rc.model}  created ${rc.created}\n`);
for (const r of v.att.rows) console.log(`${mark(r.ok)}  ${r.label}  (${r.detail})`);
console.log(`${mark(v.calls.every((c) => c.ok))}  ${v.calls.filter((c) => c.ok).length}/${v.calls.length} replies signed by the attested key over their exact bytes`);
for (const c of v.calls.filter((x) => !x.ok)) console.log(`      ${c.role}: hashes ${c.hashesOk}, signer ${c.signerOk}, attested ${c.attestedOk}`);
for (const r of v.structure) console.log(`${mark(r.ok)}  ${r.label}  (${r.detail})`);
console.log(`\nTokens per call: ${v.tokens.original} -> ${v.tokens.optimized} (saves ${v.tokens.savedPerCall})`);
v.tests.forEach((t, i) => console.log(`Test ${i + 1}: original ${t.original.pass ? 'pass' : 'FAIL'}, optimised ${t.optimized.pass ? 'pass' : 'FAIL'}  ${t.optimized.fails.join('; ')}`));
console.log(`\n${v.ok ? 'VERIFIED' : v.offline ? 'NOT VERIFIED (offline: vendor checks skipped)' : v.unreachable ? 'NOT VERIFIED (a verifier could not be reached; try again)' : 'NOT VERIFIED'}`);
process.exit(v.ok ? 0 : 1);
