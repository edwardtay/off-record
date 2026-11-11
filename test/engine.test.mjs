// Offline tests: every check runs on the recorded receipts without the network.
// Vendor checks (Intel, NVIDIA) need the network, so they are skipped here; `npm run verify` covers them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReceipt, codeChecks, canonicalJson, parseScan, checkAttestation, quoteReportData, modelAttestation } from '../web/engine.js';
import { nodeDeps } from '../scripts/deps.mjs';

const load = (f) => JSON.parse(readFileSync(new URL(`../web/${f}.json`, import.meta.url)));
const SAMPLES = ['sample-ask'];
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

test('Intel signature chain verifies in-process on every recorded quote', async () => {
  const { verifyTdxQuote } = await import('../web/dcap.js');
  for (const f of SAMPLES) {
    const rc = load(f); const m = modelAttestation(rc.attestation, rc.model);
    for (const q of [m.intel_quote, m.compose_manager_attestation.quote, rc.attestation.gateway_attestation.intel_quote]) {
      const r = verifyTdxQuote(q);
      assert.ok(r.ok, `${f}: ${JSON.stringify(r.steps)}`);
      assert.deepEqual(r.chain, ['Intel SGX PCK Certificate', 'Intel SGX PCK Platform CA', 'Intel SGX Root CA']);
    }
  }
});

test('a quote rewritten to name another key passes key binding but fails Intel\'s signature', async () => {
  const rc = load('sample-ask');
  const m = modelAttestation(rc.attestation, rc.model);
  const fake = 'ef'.repeat(32);
  m.intel_quote = m.intel_quote.slice(0, 568 * 2) + fake + m.intel_quote.slice(600 * 2);
  m.signing_public_key = m.signing_address = fake;
  const att = await checkAttestation(rc.attestation, rc.nonce, rc.model, null, null);
  assert.equal(att.rows.find((r) => r.id === 'key-bound').ok, true, 'the forgery fools the binding check');
  assert.equal(att.rows.find((r) => r.id === 'intel-sig').ok, false, 'Intel\'s signature catches it');
});

test('a swapped attestation key breaks the quote signature and the QE binding', async () => {
  const { verifyTdxQuote } = await import('../web/dcap.js');
  const rc = load('sample-ask'); const m = modelAttestation(rc.attestation, rc.model);
  // Flip one byte of the attestation key: the quote signature and the QE binding must both fail.
  const at = (636 + 64) * 2;
  const bad = m.intel_quote.slice(0, at) + (m.intel_quote[at] === '0' ? '1' : '0') + m.intel_quote.slice(at + 1);
  const r = verifyTdxQuote(bad);
  assert.equal(r.ok, false); assert.equal(r.steps.quoteSig, false); assert.equal(r.steps.qeBinding, false);
});

test('a receipt whose message was rewritten is refused', async () => {
  const rc = load('sample-ask'); rc.message = 'something else';
  const v = await offline(rc);
  assert.equal(v.structure.find((r) => r.id === 'ask').ok, false);
});

test('a receipt from the retired prompt-shortening mode is rejected with a reason', async () => {
  await assert.rejects(verifyReceipt({ ...load('sample-ask'), kind: 'optimize' }, nodeDeps, { offline: true }), /retired/);
});

/* Intel collateral, recorded from Intel's PCS (test/fixtures), checked at the time it was recorded. */
const FIX = JSON.parse(readFileSync(new URL('./fixtures/intel-collateral.json', import.meta.url)));
const AT = Date.parse(FIX.recordedAt);
const fixtureGet = (edit = (k, r) => r) => async (kind, arg = '') => {
  const f = FIX[`${kind}:${arg}`];
  if (!f) throw Object.assign(new Error(`no fixture ${kind}:${arg}`), { unreachable: true });
  return edit(kind, f.base64 ? { bytes: new Uint8Array(Buffer.from(f.base64, 'base64')), chain: f.chain } : { text: f.text, chain: f.chain });
};

test('Intel collateral: every recorded quote is up to date and not revoked', async () => {
  const { checkCollateral } = await import('../web/dcap.js');
  const rc = load('sample-ask'); const m = modelAttestation(rc.attestation, rc.model);
  for (const q of [m.intel_quote, m.compose_manager_attestation.quote, rc.attestation.gateway_attestation.intel_quote]) {
    const r = await checkCollateral(q, fixtureGet(), AT);
    assert.ok(r.ok, r.error); assert.equal(r.status, 'UpToDate'); assert.equal(r.revoked, false);
  }
});

test('Intel collateral: an edited TCB info, QE identity or CRL is refused', async () => {
  const { checkCollateral } = await import('../web/dcap.js');
  const q = modelAttestation(load('sample-ask').attestation, load('sample-ask').model).intel_quote;
  const edits = {
    tcb: (k, r) => (k === 'tcb' ? { ...r, text: r.text.replace('"OutOfDate"', '"UpToDate"') } : r),
    qe: (k, r) => (k === 'qe' ? { ...r, text: r.text.replace('"isvsvn":4', '"isvsvn":0') } : r),
    crl: (k, r) => { if (k !== 'pckcrl') return r; const b = r.bytes.slice(); b[200] ^= 1; /* inside the signed list of revoked serials */ return { ...r, bytes: b }; },
    chain: (k, r) => (k === 'tcb' ? { ...r, chain: FIX['pckcrl:platform'].chain } : r),
  };
  for (const [name, edit] of Object.entries(edits)) {
    const r = await checkCollateral(q, fixtureGet(edit), AT);
    assert.equal(r.ok, false, `${name} edit was accepted`);
  }
});

test('Intel collateral: stale collateral is refused', async () => {
  const { checkCollateral } = await import('../web/dcap.js');
  const q = modelAttestation(load('sample-ask').attestation, load('sample-ask').model).intel_quote;
  const r = await checkCollateral(q, fixtureGet(), AT + 60 * 86400000);
  assert.equal(r.ok, false); assert.match(r.error, /next update/);
});

test('Intel collateral: an unreachable service is reported as unreachable, not as a failed check', async () => {
  const { checkCollateral } = await import('../web/dcap.js');
  const q = modelAttestation(load('sample-ask').attestation, load('sample-ask').model).intel_quote;
  const r = await checkCollateral(q, async () => { throw Object.assign(new Error('down'), { unreachable: true }); }, AT);
  assert.equal(r.ok, false); assert.equal(r.unreachable, true);
});
