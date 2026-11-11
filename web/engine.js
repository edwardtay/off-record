/* Private Prompt Lab engine: runs a prompt optimisation on NEAR AI Cloud and checks
   every piece of evidence. Plain ES module with no imports, so the browser page and the
   Node scripts (verify-receipt.mjs, capture-sample.mjs) share the exact same checks.
   Hashing uses globalThis.crypto.subtle (browsers, Node 20+). Every chat call is end-to-end
   encrypted to the attested model key (e2ee.js), so NEAR AI's gateway relays only ciphertext.

   deps = {
     fetch,                          // fetch implementation
     recover(message, sig) -> 0x address (EIP-191 personal_sign recovery),
     tdxUrl, gpuUrl                  // Intel TDX quote verifier and NVIDIA NRAS endpoints
   }
*/

import { newClientKeys, encryptTo, openRequestField, decryptWith, verifyEd25519 } from './e2ee.js';

export const NEARAI = 'https://cloud-api.near.ai/v1';
const ALGO = 'ed25519';
export const DEFAULT_MODEL = 'Qwen/Qwen3.8-27B';
export const RECEIPT_VERSION = 2;

const OPTIMIZER_SYSTEM = [
  'You edit system prompts for production AI apps. Goal: the same behaviour in fewer tokens.',
  'Keep every rule, limit, number, name, tone requirement, output format and refusal. Never add a rule.',
  'Remove repetition, filler, politeness padding, rules stated twice and examples that restate a rule.',
  'Reply with JSON only, no code fence:',
  '{"optimized": "<the new system prompt>", "changes": [{"change": "<what you cut or merged>", "why": "<why behaviour stays the same>"}], "kept": ["<each hard rule you preserved, in a few words>"]}',
].join('\n');

const toHex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(strip0x(h).match(/../g) || [], (x) => parseInt(x, 16));
const strip0x = (s) => String(s || '').replace(/^0x/i, '').toLowerCase();
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
const digest = async (alg, bytes) => new Uint8Array(await globalThis.crypto.subtle.digest(alg, bytes));
export const sha256Hex = async (s) => toHex(await digest('SHA-256', new TextEncoder().encode(s)));
export const newNonce = () => toHex(globalThis.crypto.getRandomValues(new Uint8Array(32)));

/* TDX v4 quote: 48-byte header, then the TD report body. Offsets are into the whole quote. */
const Q = { tdAttributes: [168, 176], rtmr3: [520, 568], reportData: [568, 632] };
const slice = (quoteHex, [a, b]) => strip0x(quoteHex).slice(a * 2, b * 2);
export const quoteReportData = (q) => slice(q, Q.reportData);

/** The attestation for this model (NEAR AI returns one per serving instance). */
export function modelAttestation(report, model) {
  const list = report?.model_attestations || [];
  return list.find((m) => m.model_name === model) || list[0] || {};
}

/** Which kind of protection NEAR AI reports for a model. */
export function privacyKind(report) {
  if (!report || report.error) return 'external';
  const m = (report.model_attestations || [])[0] || {};
  if (m.intel_quote && m.signing_address) return 'model-tee';
  if (m.trust === 'router_attested' || m.verified) return 'routed-tee';
  return 'gateway-only';
}

/** Replay dstack's RTMR3 event log and compare with the quote, so app id and compose hash are measured, not claimed. */
export async function measuredApp(m) {
  try {
    let ev = m.event_log; if (typeof ev === 'string') ev = JSON.parse(ev);
    let r = new Uint8Array(48);
    const fields = {};
    for (const e of ev || []) {
      if (String(e.imr) !== '3') continue;
      const type = new Uint8Array(4); new DataView(type.buffer).setUint32(0, Number(e.event_type), true);
      const d = await digest('SHA-384', cat(type, new TextEncoder().encode(`:${e.event}:`), fromHex(e.event_payload)));
      r = await digest('SHA-384', cat(r, d));
      if (['app-id', 'compose-hash', 'os-image-hash', 'instance-id'].includes(e.event)) fields[e.event] = strip0x(e.event_payload);
    }
    const ok = toHex(r) === slice(m.intel_quote, Q.rtmr3);
    const attrs = fromHex(slice(m.intel_quote, Q.tdAttributes));
    return { ok, debug: (attrs[0] & 1) === 1, appId: fields['app-id'] || null, composeHash: fields['compose-hash'] || null, osImage: fields['os-image-hash'] || null };
  } catch { return { ok: false, debug: null, appId: null, composeHash: null }; }
}

export async function fetchAttestation(model, nonce, deps) {
  const r = await deps.fetch(`${NEARAI}/attestation/report?model=${encodeURIComponent(model)}&signing_algo=${ALGO}&nonce=${nonce}&include_tls_fingerprint=false`, { headers: { 'x-no-aliasing': 'true' } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) return { error: body?.error?.message || `HTTP ${r.status}` };
  return body;
}

function b64urlJson(s) {
  const b = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  return JSON.parse(typeof atob === 'function' ? atob(b) : Buffer.from(b, 'base64').toString('binary'));
}

async function postJson(deps, url, body) {
  let last;
  for (let a = 0; a < 2; a++) {
    try {
      const r = await deps.fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body });
      if (r.status >= 500) throw new Error(`HTTP ${r.status}`);
      return await r.json();
    } catch (e) { last = e; }
  }
  throw last;
}

/** Ask Intel's DCAP chain (via Phala's verifier) and NVIDIA's NRAS directly. Results stored in a receipt are never trusted. */
export async function vendorChecks(m, deps) {
  const out = { tdx: null, gpu: null };
  try {
    const j = await postJson(deps, deps.tdxUrl, JSON.stringify({ hex: strip0x(m.intel_quote) }));
    out.tdx = { verified: j?.quote?.verified === true, verified_at: j?.verified_at || null };
  } catch (e) { out.tdx = { verified: false, unreachable: true, error: `verifier unreachable (${e.message || e})` }; }
  try {
    const j = await postJson(deps, deps.gpuUrl, m.nvidia_payload);
    const claims = Array.isArray(j) && Array.isArray(j[0]) ? b64urlJson(j[0][1].split('.')[1]) : {};
    const gpus = j && typeof j[1] === 'object' ? Object.values(j[1]).map((t) => b64urlJson(String(t).split('.')[1])) : [];
    out.gpu = {
      verified: claims['x-nvidia-overall-att-result'] === true,
      nonce: claims.eat_nonce || null,
      gpus: gpus.length,
      noDebug: gpus.length > 0 && gpus.every((g) => g.dbgstat === 'disabled' && g.secboot === true),
    };
  } catch (e) { out.gpu = { verified: false, unreachable: true, error: `verifier unreachable (${e.message || e})` }; }
  return out;
}

/**
 * Checks on the attestation: fresh nonce and signing key inside the hardware quote, measured app,
 * vendor verdicts fetched now, and (when `live` is given) the same enclave app NEAR AI serves today.
 */
export async function checkAttestation(report, nonce, model, vendor, live) {
  const rows = [];
  const kind = privacyKind(report);
  const m = modelAttestation(report, model);
  const rd = m.intel_quote ? quoteReportData(m.intel_quote) : '';
  const ed = m.signing_algo === 'ed25519';
  const addr = strip0x(ed ? m.signing_public_key : m.signing_address);
  const app = m.intel_quote ? await measuredApp(m) : { ok: false };
  let gpuNonce = false;
  try { gpuNonce = strip0x(JSON.parse(m.nvidia_payload || '{}').nonce) === strip0x(nonce); } catch { /* no payload */ }
  rows.push({ id: 'model-tee', label: 'The model runs in its own TEE', ok: kind === 'model-tee' && (!m.model_name || m.model_name === model), detail: kind === 'model-tee' ? `${m.model_name || model} on Intel TDX with ${m.nvidia_payload ? 'NVIDIA confidential GPUs' : 'no GPU evidence'}` : `NEAR AI reports "${kind}" for this model` });
  rows.push({ id: 'nonce', label: 'The quote contains this run\'s nonce', ok: !!rd && rd.slice(64) === strip0x(nonce) && gpuNonce, detail: `nonce ${strip0x(nonce).slice(0, 16)}..., in the TDX quote and the GPU evidence` });
  const bound = ed ? addr.length === 64 && rd.slice(0, 64) === addr && strip0x(m.signing_address) === addr : !!addr && rd.slice(0, 40) === addr && /^0+$/.test(rd.slice(40, 64));
  rows.push({ id: 'key-bound', label: 'The quote names the model\'s key', ok: bound, detail: ed ? `Ed25519 ${addr.slice(0, 16)}..., used to sign replies and to encrypt to` : `0x${addr}` });
  rows.push({ id: 'app', label: 'The event log replays to the quote\'s RTMR3', ok: app.ok && app.debug === false, detail: app.ok ? `dstack app ${app.appId}, compose hash ${String(app.composeHash).slice(0, 16)}...${app.debug ? ', DEBUG enclave' : ', not a debug enclave'}` : 'the measured app could not be confirmed' });
  rows.push({ id: 'intel', label: 'Intel TDX quote verifies', ok: !!vendor?.tdx?.verified, unreachable: !!vendor?.tdx?.unreachable, detail: vendor?.tdx?.error || `checked just now with Phala's DCAP verifier` });
  rows.push({ id: 'nvidia', label: 'NVIDIA attests the GPUs', ok: !!vendor?.gpu?.verified && strip0x(vendor.gpu.nonce) === strip0x(nonce) && vendor.gpu.noDebug, unreachable: !!vendor?.gpu?.unreachable, detail: vendor?.gpu?.error || `${vendor?.gpu?.gpus || 0} GPU${vendor?.gpu?.gpus === 1 ? '' : 's'}, NVIDIA's signed token carries this nonce, debug off, secure boot on` });
  if (live) {
    const sameApp = !!live.app?.ok && live.app.appId === app.appId;
    rows.push({ id: 'same-app', label: 'NEAR AI serves this model from the same enclave app today', ok: sameApp, unreachable: !!live.unreachable, detail: live.unreachable ? 'NEAR AI attestation unreachable' : sameApp ? `app ${app.appId}${live.app.composeHash === app.composeHash ? ', same compose hash' : `, today's instance reports compose hash ${String(live.app.composeHash).slice(0, 16)}...`}` : `today NEAR AI serves app ${live.app?.appId || 'unknown'}` });
  }
  return { kind, ed, signer: addr ? (ed ? addr : `0x${addr}`) : null, appId: app.appId, composeHash: app.composeHash, rows };
}

/** A fresh attestation for the model, to compare the receipt's enclave app with what NEAR AI serves now. */
async function liveApp(model, deps) {
  try {
    const rep = await fetchAttestation(model, newNonce(), deps);
    if (rep.error) return { unreachable: true };
    return { app: await measuredApp(modelAttestation(rep, model)) };
  } catch { return { unreachable: true }; }
}

/**
 * One end-to-end encrypted chat completion, keeping the exact bytes sent and received.
 * Message contents are encrypted to `modelPub` (the key in the quote); the reply comes back
 * encrypted to a one-time client key. The receipt keeps the one-time secrets ("openings") so a
 * checker can open every field and confirm it says what the page shows.
 */
export async function chat({ key, model, modelPub, messages, maxTokens = 1500 }, deps) {
  const client = newClientKeys();
  const sealed = messages.map((m) => ({ role: m.role, ...encryptTo(modelPub, m.content) }));
  const request = JSON.stringify({ model, messages: sealed.map((m) => ({ role: m.role, content: m.hex })), temperature: 0, max_tokens: maxTokens, reasoning_effort: 'low' });
  const r = await deps.fetch(`${NEARAI}/chat/completions`, {
    method: 'POST', body: request,
    headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json', 'x-signing-algo': ALGO, 'x-client-pub-key': client.publicHex, 'x-model-pub-key': modelPub, 'x-encryption-version': '2', 'x-no-aliasing': 'true' },
  });
  const response = await r.text();
  if (!r.ok) throw new Error(`NEAR AI ${r.status}: ${response.slice(0, 200)}`);
  const j = JSON.parse(response);
  // The signature is stored a moment after the reply returns, so a 404 is retried.
  let signature = { error: 'signature not fetched' };
  for (let a = 0; a < 6; a++) {
    if (a) await new Promise((res) => setTimeout(res, 800 * a));
    const sr = await deps.fetch(`${NEARAI}/signature/${encodeURIComponent(j.id)}?model=${encodeURIComponent(model)}&signing_algo=${ALGO}`, { headers: { authorization: `Bearer ${key}` } });
    if (sr.ok) { signature = await sr.json(); break; }
    signature = { error: `signature HTTP ${sr.status}` };
    if (sr.status !== 404) break;
  }
  return { id: j.id, request, response, signature, e2ee: { client: client.x25519Secret, openings: sealed.map((m) => m.opening) } };
}

const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };

/**
 * The plaintext of a call. For an encrypted call, every request field is opened with its one-time
 * secret against the attested model key, and the reply is decrypted with the client key; any
 * failure marks the call as not end-to-end encrypted to that key.
 */
export function openCall(call, modelPub) {
  const req = parse(call?.request) || {};
  const res = parse(call?.response) || {};
  const msg = res.choices?.[0]?.message || {};
  if (!call?.e2ee) return { e2ee: false, model: req.model, messages: req.messages || [], reply: (msg.content || '').trim(), tokens: res.usage?.prompt_tokens ?? null };
  try {
    const messages = (req.messages || []).map((m, i) => ({ role: m.role, content: openRequestField(modelPub, call.e2ee.openings[i], m.content) }));
    if (messages.length !== (call.e2ee.openings || []).length) throw new Error('openings do not match the messages');
    const reply = msg.content ? decryptWith(call.e2ee.client, msg.content).trim() : '';
    return { e2ee: true, model: req.model, messages, reply, tokens: res.usage?.prompt_tokens ?? null };
  } catch (e) { return { e2ee: false, broken: String(e.message || e), model: req.model, messages: [], reply: '', tokens: null }; }
}

/** Signature checks for one call: the signed text is the hash of these exact bytes, and the key is the attested one. */
export async function checkCall(call, signer, deps) {
  const sig = call.signature || {};
  const [hq, hr] = await Promise.all([sha256Hex(call.request), sha256Hex(call.response)]);
  const model = parse(call.request)?.model || '';
  const hashesOk = sig.text === `${hq}:${hr}` || sig.text === `${model}:${hq}:${hr}`;
  let signerOk = false; let recovered = null;
  if (sig.signing_algo === 'ed25519') {
    recovered = strip0x(sig.signing_address);
    signerOk = !!sig.signature && verifyEd25519(String(sig.text), strip0x(sig.signature), recovered);
  } else {
    try { recovered = String(deps.recover(sig.text, sig.signature)).toLowerCase(); } catch { /* bad sig */ }
    signerOk = !!recovered && recovered === String(sig.signing_address).toLowerCase();
  }
  const attestedOk = !!recovered && strip0x(recovered) === strip0x(signer);
  return { ok: hashesOk && signerOk && attestedOk, hashesOk, signerOk, attestedOk, kind: sig.signature_kind || null, recovered };
}

/** Parse the optimiser's JSON, tolerating a code fence or stray prose. */
export function parseOptimizer(text) {
  const s = String(text).replace(/```(json)?/g, '');
  const a = s.indexOf('{'); const b = s.lastIndexOf('}');
  if (a < 0 || b <= a) return null;
  try { const j = JSON.parse(s.slice(a, b + 1)); return typeof j.optimized === 'string' && j.optimized.trim() ? j : null; } catch { return null; }
}

/** Case-insensitive must / must-not checks on a reply. "a | b" accepts either. */
export function scoreReply(reply, test) {
  const low = reply.toLowerCase();
  const has = (m) => m.split('|').map((x) => x.trim().toLowerCase()).filter(Boolean).some((x) => low.includes(x));
  const fails = [];
  for (const m of test.must || []) if (m && !has(m)) fails.push(`missing "${m}"`);
  for (const m of test.mustNot || []) if (m && has(m)) fails.push(`contains "${m}"`);
  return { pass: fails.length === 0, fails };
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); } }));
  return out;
}

/** Full run. The prompt is sent only after the attestation passes. Returns a receipt anyone can check with verifyReceipt. */
export async function runLab({ key, model = DEFAULT_MODEL, prompt, tests, onStep = () => {} }, deps) {
  const nonce = newNonce();
  onStep('attest', 'Asking NEAR AI for a fresh hardware attestation');
  const report = await fetchAttestation(model, nonce, deps);
  if (report.error) throw new Error(`Attestation failed: ${report.error}`);
  if (privacyKind(report) !== 'model-tee') throw new Error(`${model} does not run in its own TEE on NEAR AI Cloud. Pick a model marked Private.`);
  onStep('vendor', 'Checking the quote with Intel and the GPUs with NVIDIA');
  const vendor = await vendorChecks(modelAttestation(report, model), deps);
  const att = await checkAttestation(report, nonce, model, vendor);
  const bad = att.rows.filter((r) => !r.ok);
  if (bad.length) throw new Error(`Nothing was sent: the enclave did not pass "${bad[0].label}" (${bad[0].detail}).`);
  if (!att.ed) throw new Error('NEAR AI did not return an Ed25519 key for this model, so the prompt cannot be encrypted to it. Nothing was sent.');
  const modelPub = att.signer;

  onStep('optimize', 'Optimising the prompt inside the enclave');
  const optCall = await chat({ key, model, modelPub, maxTokens: 6000, messages: [{ role: 'system', content: OPTIMIZER_SYSTEM }, { role: 'user', content: prompt }] }, deps);
  const opt = parseOptimizer(openCall(optCall, modelPub).reply);
  if (!opt) throw new Error('The model did not return a usable optimised prompt. Run it again.');

  onStep('tests', `Running ${tests.length} test case${tests.length === 1 ? '' : 's'} on both prompts`);
  const jobs = tests.flatMap((t, i) => [['original', prompt], ['optimized', opt.optimized]].map(([which, sys]) => ({ i, which, sys, t })));
  const calls = await pool(jobs, 4, (j) => chat({ key, model, modelPub, maxTokens: 1500, messages: [{ role: 'system', content: j.sys }, { role: 'user', content: j.t.input }] }, deps).then((c) => ({ ...c, role: `test-${j.i}-${j.which}` })));

  return {
    version: RECEIPT_VERSION, tool: 'https://prompt20.com/tools/private-prompt/', created: new Date().toISOString(),
    model, nonce, attestation: report,
    original: prompt, optimized: opt.optimized, tests,
    calls: [{ ...optCall, role: 'optimize' }, ...calls],
  };
}

/**
 * Check a receipt from scratch. Vendor verdicts are always fetched now, never read from the receipt.
 * `offline` skips the network: the verdict can then never be VERIFIED.
 */
export async function verifyReceipt(rc, deps, { offline = false } = {}) {
  const m = modelAttestation(rc.attestation, rc.model);
  const [vendor, live] = offline ? [null, null] : await Promise.all([vendorChecks(m, deps), liveApp(rc.model, deps)]);
  const att = await checkAttestation(rc.attestation, rc.nonce, rc.model, vendor, live);
  if (offline) att.rows.filter((r) => r.id === 'intel' || r.id === 'nvidia').forEach((r) => { r.detail = 'not checked (offline)'; });

  const calls = await Promise.all(rc.calls.map(async (c) => ({ role: c.role, id: c.id, ...(await checkCall(c, att.signer, deps)) })));

  // Structure: one optimiser call, then exactly one original and one optimised call per test, each
  // sending the prompt and test message it claims, all to the receipt's model.
  const tests = Array.isArray(rc.tests) ? rc.tests : [];
  const want = ['optimize', ...tests.flatMap((_, i) => [`test-${i}-original`, `test-${i}-optimized`])];
  const roles = rc.calls.map((c) => c.role);
  const rolesOk = tests.length > 0 && roles.length === want.length && want.every((r) => roles.filter((x) => x === r).length === 1);
  // Every field is opened against the attested key; structure checks run on the opened plaintext.
  const opened = new Map(rc.calls.map((c) => [c, openCall(c, att.signer)]));
  const req = (c) => (c ? opened.get(c) : null) || { messages: [] };
  const modelOk = rc.calls.every((c) => req(c).model === rc.model);
  const e2eeCount = rc.calls.filter((c) => req(c).e2ee).length;
  const optCall = rc.calls.find((c) => c.role === 'optimize');
  const signed = parseOptimizer(req(optCall).reply) || {};
  const optOk = signed.optimized === rc.optimized && req(optCall).messages?.[1]?.content === rc.original;
  const sentOk = rolesOk && tests.every((t, i) => ['original', 'optimized'].every((w) => {
    const msgs = req(rc.calls.find((c) => c.role === `test-${i}-${w}`)).messages || [];
    return msgs.length === 2 && msgs[0].content === (w === 'original' ? rc.original : rc.optimized) && msgs[1].content === t.input;
  }));

  const results = tests.map((t, i) => {
    const side = (w) => { const c = rc.calls.find((x) => x.role === `test-${i}-${w}`); if (!c) return null; const o = req(c); return { reply: o.reply, tokens: o.tokens, ...scoreReply(o.reply, t) }; };
    return { ...t, original: side('original'), optimized: side('optimized') };
  });
  const saved = results.map((t) => (t.original?.tokens ?? 0) - (t.optimized?.tokens ?? 0));
  const structure = [
    { id: 'e2ee', label: 'Every message was encrypted to the attested key', ok: e2eeCount === rc.calls.length && rc.calls.length > 0, detail: `${e2eeCount} of ${rc.calls.length} calls: each prompt field opens only with the key in the quote, each reply only with this run's one-time key` },
    { id: 'optimized', label: 'The optimised prompt shown is the one the model returned', ok: optOk, detail: 'read from the signed optimiser reply' },
    { id: 'tests', label: 'Each test ran once per prompt, with the message shown', ok: sentOk && modelOk, detail: `${tests.length} test${tests.length === 1 ? '' : 's'}, ${rc.calls.length} signed calls, all to ${rc.model}` },
  ];
  const allOk = !offline && att.rows.every((r) => r.ok) && calls.every((c) => c.ok) && structure.every((r) => r.ok);
  const unreachable = att.rows.some((r) => !r.ok && r.unreachable);
  return {
    ok: allOk, unreachable, offline, att, calls, structure, tests: results,
    signed: { changes: Array.isArray(signed.changes) ? signed.changes : [], kept: Array.isArray(signed.kept) ? signed.kept : [] },
    tokens: { original: results[0]?.original?.tokens ?? null, optimized: results[0]?.optimized?.tokens ?? null, savedPerCall: saved.length ? Math.round(saved.reduce((a, b) => a + b, 0) / saved.length) : 0 },
  };
}
