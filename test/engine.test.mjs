// Offline tests: every check runs on the recorded receipts without the network.
// Vendor checks (Intel, NVIDIA) need the network, so they are skipped here; `npm run verify` covers them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReceipt, codeChecks, canonicalJson, parseScan, checkAttestation, quoteReportData, modelAttestation } from '../web/engine.js';
import { nodeDeps } from '../scripts/deps.mjs';

const load = (f) => JSON.parse(readFileSync(new URL(`../web/${f}.json`, import.meta.url)));
const SAMPLES = ['sample-ask', 'sample-run', 'sample-extreme'];
const VENDOR = new Set(['intel', 'nvidia', 'same-app']);
const offline = (rc) => verifyReceipt(rc, nodeDeps, { offline: true });

for (const f of SAMPLES) {
  test(`${f}: every offline check passes`, async () => {
    const v = await offline(load(f));
    for (const r of v.att.rows.filter((x) => !VENDOR.has(x.id))) assert.ok(r.ok, r.label);
    for (const c of v.calls) assert.ok(c.ok, `call ${c.role}`);
    for (const r of v.structure) assert.ok(r.ok, r.label);
    assert.equal(v.ok, false, 'offline can never be VERIFIED');
  });

  test(`${f}: what code is running links up`, async () => {
    const rc = load(f);
    const { compose, deploy, gateway } = await codeChecks(rc.attestation, rc.nonce, rc.model, nodeDeps, { offline: true });
    assert.ok(compose.ok && compose.configOk, 'compose file matches MRCONFIGID and RTMR3');
    assert.ok(deploy.hashOk && deploy.nonceOk && deploy.sameVm, 'deploy log bound to the nonce, same VM');
    assert.ok(gateway.ok, 'gateway quote names its key and the nonce');
  });
}

test('a flipped byte in an encrypted reply is refused', async () => {
  const rc = load('sample-ask');
  const c = rc.calls[0]; const i = c.response.indexOf('"content"') + 12;
  c.response = c.response.slice(0, i) + (c.response[i] === 'a' ? 'b' : 'a') + c.response.slice(i + 1);
  const v = await offline(rc);
  assert.equal(v.calls[0].ok, false);
});

test('an old quote offered against a new nonce is refused', async () => {
  const rc = load('sample-ask');
  const att = await checkAttestation(rc.attestation, 'ab'.repeat(32), rc.model, null, null);
  assert.equal(att.rows.find((r) => r.id === 'nonce').ok, false);
});

test('a key the quote does not contain is refused', async () => {
  const rc = load('sample-ask');
  const m = modelAttestation(rc.attestation, rc.model);
  m.signing_public_key = m.signing_address = 'cd'.repeat(32);
  const att = await checkAttestation(rc.attestation, rc.nonce, rc.model, null, null);
  assert.equal(att.rows.find((r) => r.id === 'key-bound').ok, false);
});

test('an edited deploy log no longer matches its quote', async () => {
  const rc = load('sample-ask');
  const m = modelAttestation(rc.attestation, rc.model);
  m.compose_manager_attestation.actions[0].image = 'evil/image@sha256:' + '0'.repeat(64);
  const { deploy } = await codeChecks(rc.attestation, rc.nonce, rc.model, nodeDeps, { offline: true });
  assert.equal(deploy.ok, false);
});

test('an edited compose file no longer matches the quote', async () => {
  const rc = load('sample-ask');
  const m = modelAttestation(rc.attestation, rc.model);
  m.info.tcb_info.app_compose = m.info.tcb_info.app_compose.replace('compose-manager', 'compose-mangler');
  const { compose } = await codeChecks(rc.attestation, rc.nonce, rc.model, nodeDeps, { offline: true });
  assert.equal(compose.ok, false);
});

test('canonical JSON matches Python json.dumps(sort_keys, compact, ensure_ascii=False)', () => {
  assert.equal(canonicalJson({ b: 1, a: [true, null, 'é "q"'], c: { z: 0, y: 'x' } }), '{"a":[true,null,"é \\"q\\""],"b":1,"c":{"y":"x","z":0}}');
});

test('the report data holds the key and then the nonce', () => {
  const rc = load('sample-ask');
  const m = modelAttestation(rc.attestation, rc.model);
  assert.equal(quoteReportData(m.intel_quote), m.signing_public_key + rc.nonce);
});

test('the sensitive-item scan keeps only text that is in the message', () => {
  const items = parseScan('{"items":[{"text":"Mei Lin","type":"name"},{"text":"made up","type":"name"}]}', 'Patient Mei Lin, 54');
  assert.deepEqual(items, [{ text: 'Mei Lin', type: 'name' }]);
});
