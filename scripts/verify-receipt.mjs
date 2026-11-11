// Check an Off Record receipt from scratch, no API key needed.
// Usage: node scripts/verify-receipt.mjs web/sample-chat.json [--tamper | --swap-message] [--offline]
//   Intel's and NVIDIA's verifiers and NEAR AI's live attestation are always asked now.
//   --tamper        flip one byte in the encrypted reply first, to watch the check fail
//   --swap-message  rewrite the message shown in the receipt, to watch the check fail
//   --offline    skip the network checks (the verdict is then never VERIFIED)
import { readFileSync } from 'node:fs';
import { verifyReceipt } from '../web/engine.js';
import { nodeDeps } from './deps.mjs';

const file = process.argv[2] || 'web/sample-chat.json';
const rc = JSON.parse(readFileSync(file, 'utf8'));
if (process.argv.includes('--tamper')) {
  const c = rc.calls[0];
  const i = /"content":\s*"[0-9a-f]/.exec(c.response).index + c.response.slice(/"content":\s*"[0-9a-f]/.exec(c.response).index).indexOf('"', 10) + 1;
  c.response = c.response.slice(0, i) + (c.response[i] === 'a' ? 'b' : 'a') + c.response.slice(i + 1);
  console.log('Tampered: flipped one byte in the encrypted reply.\n');
}
if (process.argv.includes('--swap-message')) {
  if (rc.turns) rc.turns[0] = 'A different message than the one the model answered'; else rc.message = 'A different message than the one the model answered';
  console.log('Tampered: rewrote the message shown in the receipt.\n');
}
const v = await verifyReceipt(rc, nodeDeps, { offline: process.argv.includes('--offline') });
const mark = (ok) => (ok ? 'PASS' : 'FAIL');
console.log(`Receipt ${file}\nmodel ${rc.model}  created ${rc.created}\n`);
for (const r of v.att.rows) console.log(`${mark(r.ok)}  ${r.label}  (${r.detail})`);
console.log(`${mark(v.calls.every((c) => c.ok))}  ${v.calls.filter((c) => c.ok).length}/${v.calls.length} replies signed by the attested key over their exact bytes`);
for (const c of v.calls.filter((x) => !x.ok)) console.log(`      ${c.role}: hashes ${c.hashesOk}, signer ${c.signerOk}, attested ${c.attestedOk}`);
for (const r of v.structure) console.log(`${mark(r.ok)}  ${r.label}  (${r.detail})`);
const { compose: cc, deploy: dl, gateway: gw } = v.code;
const src = dl.source;
console.log('\nWhat code is running');
console.log(`${mark(cc.ok)}  compose file ${cc.name} hashes to the quote's MRCONFIGID and RTMR3 compose hash (${cc.hash.slice(0, 16)}...)`);
console.log(`${dl.ok && dl.intel === null ? '?   ' : mark(dl.ok && dl.intel === true)}  deploy log: ${dl.entries} actions hashed into a second quote with this nonce, same VM, Intel signature ${dl.sig ? 'checks out' : 'FAILS'}, Intel collateral ${dl.intel === null ? 'not checked' : dl.intel ? 'trusted, not revoked' : 'FAILS'}`);
if (src) console.log(`${mark(src.ok)}  ${src.service || 'model container'} from ${src.url}: GitHub file matches the logged sha256\n      engine ${src.image}${src.weights ? `, weights ${src.weights}${src.revision ? `@${src.revision.slice(0, 7)}` : ''}` : ''}`);
console.log(`${gw.ok && gw.intel === null ? '?   ' : mark(gw.ok && gw.intel === true)}  gateway enclave: quote names its key ${gw.key?.slice(0, 16)}... and this nonce, Intel signature ${gw.sig ? 'checks out' : 'FAILS'}, Intel collateral ${gw.intel === null ? 'not checked' : gw.intel ? 'trusted, not revoked' : 'FAILS'}\n`);
console.log(`${(v.rc?.turns || []).length} turn(s), each sent with the earlier turns and their signed replies`);
console.log(`Sensitive items found inside the enclave: ${(v.sensitive || []).map((x) => x.type).join(', ') || 'none'}`);
console.log(`\nReply (decrypted): ${String(v.reply).replace(/\s+/g, ' ').slice(0, 300)}`);
// A definite failure (a changed byte, a wrong key, a swapped message) is reported ahead of an outage.
const definite = v.att.rows.some((r) => !r.ok && !r.unreachable && !(v.offline && (r.id === 'intel' || r.id === 'nvidia'))) || !v.code?.compose?.ok || v.calls.some((c) => !c.ok) || v.structure.some((r) => !r.ok);
console.log(`\n${v.ok ? 'VERIFIED' : definite ? 'NOT VERIFIED (a check failed above)' : v.offline ? 'NOT VERIFIED (offline: vendor checks skipped)' : v.unreachable ? 'NOT VERIFIED (a verifier could not be reached; try again)' : 'NOT VERIFIED'}`);
process.exit(v.ok ? 0 : 1);
