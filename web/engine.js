/* Private Prompt Lab engine: runs a prompt optimisation on NEAR AI Cloud and checks
   every piece of evidence. Plain ES module with no imports, so the browser page and the
   Node scripts (verify-receipt.mjs, capture-sample.mjs) share the exact same checks.
   Hashing uses globalThis.crypto.subtle (browsers, Node 20+). Every chat call is end-to-end
   encrypted to the attested model key (e2ee.js), so NEAR AI's gateway relays only ciphertext.

   deps = {
     fetch,                          // fetch implementation
     tdxUrl, gpuUrl                  // Intel TDX quote verifier and NVIDIA NRAS endpoints
   }
*/

import { newClientKeys, encryptTo, openRequestField, decryptWith, verifyEd25519 } from './e2ee.js?v=11';

export const NEARAI = 'https://cloud-api.near.ai/v1';
const ALGO = 'ed25519';
export const DEFAULT_MODEL = 'Qwen/Qwen3.8-27B';
export const RECEIPT_VERSION = 2;

const OPTIMIZER_BASE = [
  'You edit system prompts for production AI apps. Goal: the same behaviour in fewer tokens.',
  'Keep every rule, limit, number, name, tone requirement, output format and refusal. Never add a rule.',
  'Remove repetition, filler, politeness padding, rules stated twice and examples that restate a rule.',
];
const OPTIMIZER_AGGRESSIVE = [
  'You edit system prompts for production AI apps. Goal: the shortest prompt that still works.',
  'Cut as hard as you can: aim for under a third of the original tokens. Keep only the rules you judge essential and drop details a capable model would infer.',
];
const OPTIMIZER_FORMAT = [
  'Reply with JSON only, no code fence:',
  '{"optimized": "<the new system prompt>", "changes": [{"change": "<what you cut or merged>", "why": "<why behaviour stays the same>"}], "kept": ["<each hard rule you preserved, in a few words>"]}',
];
const OPTIMIZER_EXTREME = [
  'You edit system prompts for production AI apps. Hard budget: the new prompt must be 40 words or fewer.',
  'Fit the budget whatever it takes: merge, compress and drop the rules you judge least important.',
];
const SCAN_SYSTEM = [
  'Find every sensitive item in the user\'s text: person names, ages, dates of birth, contact details, addresses, ID or account numbers, health data (conditions, test results, measurements), medications, financial details, employer or school names.',
  'Copy each item exactly as it appears, the shortest span that is sensitive. Do not add items that are not in the text.',
  'Reply with JSON only, no code fence: {"items": [{"text": "<exact span>", "type": "name|age|date|contact|id|health|medication|financial|organisation|other"}]}',
].join('\n');

/** Sensitive items from the enclave's scan, kept only if each appears verbatim in the message. */
export function parseScan(text, message) {
  const s = String(text).replace(/```(json)?/g, ''); const a = s.indexOf('{'); const b = s.lastIndexOf('}');
  if (a < 0 || b <= a) return [];
  try {
    const items = JSON.parse(s.slice(a, b + 1)).items || [];
    const seen = new Set();
    return items.filter((it) => it && typeof it.text === 'string' && it.text.trim().length > 1 && message.includes(it.text.trim()) && !seen.has(it.text.trim()) && seen.add(it.text.trim()))
      .map((it) => ({ text: it.text.trim(), type: String(it.type || 'other').toLowerCase() }));
  } catch { return []; }
}

export const MODES = { careful: 'Careful', aggressive: 'Aggressive', extreme: 'Extreme (40 words)' };
const optimizerSystem = (mode) => [...({ aggressive: OPTIMIZER_AGGRESSIVE, extreme: OPTIMIZER_EXTREME }[mode] || OPTIMIZER_BASE), ...OPTIMIZER_FORMAT].join('\n');

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
  // Only NEAR AI's own statement counts as external; a network or server error is unknown, never "not private".
  if (!report) return 'unknown';
  if (report.error) return /external provider/i.test(report.error) ? 'external' : 'unknown';
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

const NRAS_JWKS = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';
const b64urlBytes = (s) => { const b = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4); const bin = typeof atob === 'function' ? atob(b) : Buffer.from(b, 'base64').toString('binary'); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };

/** Verify an NVIDIA attestation token (ES384) against NVIDIA's published keys, plus issuer and expiry. */
async function verifyNvidiaJwt(token, jwks) {
  try {
    const [h, p, sig] = String(token).split('.');
    const header = JSON.parse(new TextDecoder().decode(b64urlBytes(h)));
    const claims = JSON.parse(new TextDecoder().decode(b64urlBytes(p)));
    const jwk = (jwks?.keys || []).find((k) => k.kid === header.kid);
    if (!jwk || header.alg !== 'ES384') return { ok: false, claims, why: 'unknown signing key' };
    const key = await globalThis.crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-384', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
    const sigOk = await globalThis.crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, b64urlBytes(sig), new TextEncoder().encode(`${h}.${p}`));
    // Each check asks NVIDIA again, so the token must be unexpired now.
    const fresh = typeof claims.exp === 'number' && claims.exp > Date.now() / 1000;
    return { ok: sigOk && claims.iss === 'https://nras.attestation.nvidia.com' && fresh, claims };
  } catch (e) { return { ok: false, why: String(e.message || e) }; }
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
    const [j, jwks] = await Promise.all([postJson(deps, deps.gpuUrl, m.nvidia_payload), deps.fetch(deps.jwksUrl || NRAS_JWKS).then((r) => r.json())]);
    // Every token NVIDIA returns (the platform result and one per GPU) must carry NVIDIA's signature.
    const overall = Array.isArray(j) && Array.isArray(j[0]) ? await verifyNvidiaJwt(j[0][1], jwks) : { ok: false };
    const gpuTokens = j && typeof j[1] === 'object' ? await Promise.all(Object.values(j[1]).map((t) => verifyNvidiaJwt(t, jwks))) : [];
    const claims = overall.claims || {};
    out.gpu = {
      verified: overall.ok && gpuTokens.length > 0 && gpuTokens.every((g) => g.ok) && claims['x-nvidia-overall-att-result'] === true,
      signed: overall.ok && gpuTokens.every((g) => g.ok),
      nonce: claims.eat_nonce || null,
      gpus: gpuTokens.length,
      noDebug: gpuTokens.length > 0 && gpuTokens.every((g) => g.claims?.dbgstat === 'disabled' && g.claims?.secboot === true),
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
  rows.push({ id: 'nvidia', label: 'NVIDIA attests the GPUs', ok: !!vendor?.gpu?.verified && strip0x(vendor.gpu.nonce) === strip0x(nonce) && vendor.gpu.noDebug, unreachable: !!vendor?.gpu?.unreachable, detail: vendor?.gpu?.error || `${vendor?.gpu?.gpus || 0} GPU${vendor?.gpu?.gpus === 1 ? '' : 's'}, each token's NVIDIA signature checked here, this nonce, debug off, secure boot on` });
  if (live) {
    const sameApp = !!live.app?.ok && live.app.appId === app.appId;
    rows.push({ id: 'same-app', label: 'NEAR AI reports the same enclave app for this model today', ok: sameApp, unreachable: !!live.unreachable, detail: live.unreachable ? 'NEAR AI attestation unreachable' : sameApp ? `app ${app.appId}${live.app.composeHash === app.composeHash ? ', same compose hash' : `, today's instance reports compose hash ${String(live.app.composeHash).slice(0, 16)}...`}` : `today NEAR AI serves app ${live.app?.appId || 'unknown'}` });
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

/* ---- What code runs: the compose file, NEAR AI's deploy log and the gateway's own enclave ---- */

/** JSON as Python json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) writes it: the form NEAR AI hashes. */
export function canonicalJson(v) {
  const str = (x) => JSON.stringify(x);
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${str(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  return str(v);
}
const MEASURE = [184, 232]; // MRTD
const MRCONFIG = [232, 280]; // MRCONFIGID: dstack puts 0x01 || sha256(app_compose) here
const RTMRS = [376, 568];   // RTMR0 to RTMR3
const servesModel = (svc, model) => {
  const name = String(model).split('/').pop();
  const keys = [compact(name), compact(name.split('-').slice(0, 2).join('-'))];
  return /^model-/.test(svc || '') && [...keys, ...keys.map((k) => k.replace(/^deepseek/, 'ds'))].some((k) => compact(svc).includes(k));
};
const compact = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
const imagesIn = (compose) => [...new Set((String(compose).match(/image:\s*["']?([^\s"']+)/g) || []).map((x) => x.replace(/image:\s*["']?/, '').replace(/^\$\{[A-Z_]+:-(.+)\}$/, '$1')))];

/** The compose file the enclave booted: it must hash to the compose hash measured into RTMR3. */
export async function composeCheck(att) {
  const app = await measuredApp(att);
  const compose = att?.info?.tcb_info?.app_compose;
  if (!compose || !app.ok) return { ok: false, detail: 'no measured compose file' };
  const hash = await sha256Hex(compose);
  let images = []; let name = att.info.app_name || '';
  try { const c = JSON.parse(compose); images = imagesIn(c.docker_compose_file); name = c.name || name; } catch { /* not JSON */ }
  const configOk = slice(att.intel_quote, MRCONFIG) === `01${hash}`.padEnd(96, '0');
  return { ok: hash === app.composeHash && configOk, configOk, hash, name, images, appId: app.appId };
}

/**
 * NEAR AI starts the model containers at runtime with a "compose manager". Its action log is hashed
 * (sha256 of the canonical JSON) and the hash plus this run's nonce sit in a second TDX quote from the
 * same VM (same MRTD and RTMRs as the model's quote).
 */
export async function deployLog(att, nonce, model) {
  const cm = att?.compose_manager_attestation;
  if (!cm || !Array.isArray(cm.actions)) return { ok: false, present: false, detail: 'no deploy log in this attestation' };
  const hash = await sha256Hex(canonicalJson(cm.actions));
  const rd = cm.quote ? quoteReportData(cm.quote) : '';
  const sameVm = !!cm.quote && slice(cm.quote, MEASURE) === slice(att.intel_quote, MEASURE) && slice(cm.quote, RTMRS) === slice(att.intel_quote, RTMRS);
  const running = new Map();
  for (const a of cm.actions) {
    if (a.action === 'compose_down' && !a.services) { for (const [svc, up] of running) if (up.file === a.file) running.delete(svc); }
    for (const svc of a.services || []) { if (a.action === 'compose_up') running.set(svc, a); else if (a.action === 'compose_down') running.delete(svc); }
  }
  let mine = [...running.entries()].filter(([svc]) => servesModel(svc, model)).sort((x, y) => String(y[1].timestamp).localeCompare(String(x[1].timestamp)));
  // A compose_up with no service list starts the whole file: look for the model's service inside it.
  const whole = [...cm.actions].reverse().find((a) => a.action === 'compose_up' && !a.services && a.file);
  if (!mine.length && whole) mine = [[null, whole]];
  const last = cm.actions[cm.actions.length - 1] || {};
  return {
    ok: hash === strip0x(cm.actions_hash) && rd === hash + strip0x(nonce) && sameVm,
    present: true, hashOk: hash === strip0x(cm.actions_hash), nonceOk: rd === hash + strip0x(nonce), sameVm,
    entries: cm.actions.length, quote: cm.quote,
    latest: { at: last.timestamp || null, tag: last.tag || null, commit: last.commit || null, file: last.file || null },
    containers: mine.map(([svc, a]) => ({ service: svc, at: a.timestamp, tag: a.tag, commit: a.commit, file: a.file, fileSha256: a.file_sha256 })),
    services: running.size,
  };
}

/* Minimal docker-compose reading: a service's image, following "<<: *anchor" merges, and its model tags. */
function composeService(yaml, name) {
  const lines = String(yaml).split('\n');
  const block = (start, indent) => { const out = []; for (let i = start + 1; i < lines.length; i++) { const l = lines[i]; if (l.trim() && !l.startsWith(' '.repeat(indent + 1))) break; out.push(l); } return out; };
  const findImage = (start, indent, depth = 0) => {
    const b = block(start, indent);
    const img = b.find((l) => new RegExp(`^ {${indent + 2}}image:`).test(l));
    if (img) return { name: img.split('image:')[1].trim().replace(/^["']|["']$/g, ''), built: b.some((l) => new RegExp(`^ {${indent + 2}}build:`).test(l)) };
    const merge = b.map((l) => l.match(new RegExp(`^ {${indent + 2}}<<: \\*([\\w-]+)`))).find(Boolean);
    if (!merge || depth > 4) return null;
    const at = lines.findIndex((l) => new RegExp(`^( *)[\\w-]+: &${merge[1]}\\s*$`).test(l));
    return at < 0 ? null : findImage(at, lines[at].match(/^ */)[0].length, depth + 1);
  };
  const at = lines.findIndex((l) => l === `  ${name}:`);
  if (at < 0) return null;
  const text = block(at, 2).join('\n');
  const tag = (k) => (text.match(new RegExp(`"${k}:([^"]+)"`)) || [])[1] || null;
  const img = findImage(at, 2) || {};
  return { image: img.name || null, built: !!img.built, weights: tag('model'), revision: tag('model_revision') };
}

/** Fetch the deploy file from NEAR AI's public repo at the logged commit; it must hash to the logged sha256. */
export async function deployFile(container, model, deps) {
  if (!container?.commit || !container.file) return null;
  try {
    const r = await deps.fetch(`https://raw.githubusercontent.com/nearai/cvm-compose-files/${container.commit}/${container.file}`);
    if (!r.ok) return { ok: false, error: `GitHub HTTP ${r.status}` };
    const text = await r.text();
    const hash = await sha256Hex(text);
    const service = container.service || (text.match(/^  (model-[\w.-]+):\s*$/gm) || []).map((l) => l.trim().slice(0, -1)).find((svc) => servesModel(svc, model)) || null;
    return { ok: hash === strip0x(container.fileSha256), service, url: `https://github.com/nearai/cvm-compose-files/blob/${container.commit}/${container.file}`, ...(service ? composeService(text, service) || {} : {}) };
  } catch (e) { return { ok: false, unreachable: true, error: String(e.message || e) }; }
}

/** NEAR AI's gateway (which relays the ciphertext) runs in its own enclave: its quote names its key and this nonce. */
export async function gatewayCheck(report, nonce) {
  const g = report?.gateway_attestation;
  if (!g?.intel_quote) return { ok: false, present: false };
  const rd = quoteReportData(g.intel_quote);
  const key = strip0x(g.signing_address);
  const app = await measuredApp(g);
  const compose = await composeCheck(g);
  return { ok: key.length === 64 && rd === key + strip0x(nonce) && app.ok && app.debug === false && compose.ok, present: true, key, app, compose, quote: g.intel_quote };
}

/** All three, with Intel asked now about the deploy-log quote and the gateway quote. */
export async function codeChecks(report, nonce, model, deps, { offline = false } = {}) {
  const m = modelAttestation(report, model);
  const [compose, deploy, gateway] = await Promise.all([composeCheck(m), deployLog(m, nonce, model), gatewayCheck(report, nonce)]);
  const intel = async (q) => {
    if (offline || !q) return null;
    try { const j = await postJson(deps, deps.tdxUrl, JSON.stringify({ hex: strip0x(q) })); return j?.quote?.verified === true; } catch { return null; }
  };
  [deploy.intel, gateway.intel, deploy.source] = await Promise.all([intel(deploy.quote), intel(gateway.quote), offline ? null : deployFile(deploy.containers?.[0], model, deps)]);
  delete deploy.quote; delete gateway.quote;
  return { compose, deploy, gateway };
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
  // Every run is Ed25519 (NEAR AI E2EE v2); any other signature kind fails closed.
  const recovered = sig.signing_algo === 'ed25519' ? strip0x(sig.signing_address) : null;
  const signerOk = !!recovered && !!sig.signature && verifyEd25519(String(sig.text), strip0x(sig.signature), recovered);
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
export async function runLab({ key, model = DEFAULT_MODEL, prompt, tests, mode = 'careful', onStep = () => {} }, deps) {
  const nonce = newNonce();
  onStep('attest', 'Asking NEAR AI for a fresh hardware attestation');
  const report = await fetchAttestation(model, nonce, deps);
  if (report.error) throw new Error(/external provider/i.test(report.error) ? `Refused before sending: NEAR AI runs ${model} at an outside provider, not in its own TEE. Nothing was sent.` : `Attestation failed, nothing was sent: ${report.error}`);
  if (privacyKind(report) !== 'model-tee') throw new Error(`${model} does not run in its own TEE on NEAR AI Cloud. Pick a model marked Private.`);
  onStep('vendor', 'Checking the quote with Intel and the GPUs with NVIDIA');
  const vendor = await vendorChecks(modelAttestation(report, model), deps);
  const att = await checkAttestation(report, nonce, model, vendor);
  const bad = att.rows.filter((r) => !r.ok);
  if (bad.length) throw new Error(`Nothing was sent: the enclave did not pass "${bad[0].label}" (${bad[0].detail}).`);
  if (!att.ed) throw new Error('NEAR AI did not return an Ed25519 key for this model, so the prompt cannot be encrypted to it. Nothing was sent.');
  const modelPub = att.signer;

  onStep('optimize', 'Optimising the prompt inside the enclave');
  const optCall = await chat({ key, model, modelPub, maxTokens: 6000, messages: [{ role: 'system', content: optimizerSystem(mode) }, { role: 'user', content: prompt }] }, deps);
  // Authenticate the optimiser's reply before its output is used in any further call.
  const optCheck = await checkCall(optCall, modelPub, deps);
  const optOpen = openCall(optCall, modelPub);
  if (!optCheck.ok || !optOpen.e2ee) throw new Error('The optimiser reply did not verify (signature or encryption), so no test calls were sent.');
  const opt = parseOptimizer(optOpen.reply);
  if (!opt) throw new Error('The model did not return a usable optimised prompt. Run it again.');

  onStep('tests', `Running ${tests.length} test case${tests.length === 1 ? '' : 's'} on both prompts`);
  const jobs = tests.flatMap((t, i) => [['original', prompt], ['optimized', opt.optimized]].map(([which, sys]) => ({ i, which, sys, t })));
  const calls = await pool(jobs, 4, (j) => chat({ key, model, modelPub, maxTokens: 1500, messages: [{ role: 'system', content: j.sys }, { role: 'user', content: j.t.input }] }, deps).then((c) => ({ ...c, role: `test-${j.i}-${j.which}` })));

  return {
    version: RECEIPT_VERSION, tool: 'https://prompt20.com/tools/private-prompt/', created: new Date().toISOString(),
    kind: 'optimize', model, mode, nonce, attestation: report,
    original: prompt, optimized: opt.optimized, tests,
    calls: [{ ...optCall, role: 'optimize' }, ...calls],
  };
}

/** Ask one sensitive question privately: same checks before sending, one encrypted call, a receipt. */
export async function runAsk({ key, model = DEFAULT_MODEL, system = '', message, onStep = () => {} }, deps) {
  const nonce = newNonce();
  onStep('attest', 'Asking NEAR AI for a fresh hardware attestation');
  const report = await fetchAttestation(model, nonce, deps);
  if (report.error) throw new Error(/external provider/i.test(report.error) ? `Refused before sending: NEAR AI runs ${model} at an outside provider, not in its own TEE. Nothing was sent.` : `Attestation failed, nothing was sent: ${report.error}`);
  if (privacyKind(report) !== 'model-tee') throw new Error(`${model} does not run in its own TEE on NEAR AI Cloud. Nothing was sent.`);
  onStep('vendor', 'Checking the quote with Intel and the GPUs with NVIDIA');
  const att = await checkAttestation(report, nonce, model, await vendorChecks(modelAttestation(report, model), deps));
  const bad = att.rows.filter((r) => !r.ok);
  if (bad.length) throw new Error(`Nothing was sent: the enclave did not pass "${bad[0].label}" (${bad[0].detail}).`);
  if (!att.ed) throw new Error('NEAR AI did not return an Ed25519 key for this model, so the message cannot be encrypted to it. Nothing was sent.');
  onStep('optimize', 'Sending your message, encrypted to the enclave key');
  const messages = [...(system.trim() ? [{ role: 'system', content: system }] : []), { role: 'user', content: message }];
  // Two encrypted calls in parallel: the answer, and a scan that lists the sensitive items in the message.
  const [call, scan] = await Promise.all([
    chat({ key, model, modelPub: att.signer, maxTokens: 3000, messages }, deps),
    chat({ key, model, modelPub: att.signer, maxTokens: 2000, messages: [{ role: 'system', content: SCAN_SYSTEM }, { role: 'user', content: message }] }, deps),
  ]);
  return { version: RECEIPT_VERSION, kind: 'ask', tool: 'https://prompt20.com/tools/private-prompt/', created: new Date().toISOString(), model, nonce, attestation: report, system, message, calls: [{ ...call, role: 'ask' }, { ...scan, role: 'scan' }] };
}

/**
 * Check a receipt from scratch. Vendor verdicts are always fetched now, never read from the receipt.
 * `offline` skips the network: the verdict can then never be VERIFIED.
 */
export async function verifyReceipt(rc, deps, { offline = false } = {}) {
  const m = modelAttestation(rc.attestation, rc.model);
  const [vendor, live, code] = await Promise.all(offline ? [null, null, codeChecks(rc.attestation, rc.nonce, rc.model, deps, { offline })] : [vendorChecks(m, deps), liveApp(rc.model, deps), codeChecks(rc.attestation, rc.nonce, rc.model, deps)]);
  const att = await checkAttestation(rc.attestation, rc.nonce, rc.model, vendor, live);
  if (offline) att.rows.filter((r) => r.id === 'intel' || r.id === 'nvidia').forEach((r) => { r.detail = 'not checked (offline)'; });

  const calls = await Promise.all(rc.calls.map(async (c) => ({ role: c.role, id: c.id, ...(await checkCall(c, att.signer, deps)) })));

  if (rc.kind === 'ask') {
    const roles = rc.calls.map((c) => c.role);
    const shapeOk = roles[0] === 'ask' && (roles.length === 1 || (roles.length === 2 && roles[1] === 'scan'));
    const call = shapeOk ? rc.calls[0] : null;
    const o = call ? openCall(call, att.signer) : { messages: [] };
    const want = [...(String(rc.system || '').trim() ? [rc.system] : []), rc.message];
    const scanCall = shapeOk && roles[1] === 'scan' ? rc.calls[1] : null;
    const so = scanCall ? openCall(scanCall, att.signer) : null;
    const scanOk = !scanCall || (so.e2ee && so.model === rc.model && so.messages.length === 2 && so.messages[1].content === rc.message);
    const sentOk = !!call && o.model === rc.model && o.messages.length === want.length && o.messages.every((m, i) => m.content === want[i]) && scanOk;
    const sensitive = so && scanOk ? parseScan(so.reply, rc.message) : null;
    const structure = [
      { id: 'e2ee', label: 'The message was encrypted to the attested key', ok: !!o.e2ee && (!so || so.e2ee), detail: 'every call opens only with the key in the quote; replies only with this run\'s one-time key' },
      { id: 'ask', label: 'The message, reply and sensitive-item scan shown are the ones signed', ok: sentOk, detail: `${rc.calls.length} signed call${rc.calls.length === 1 ? '' : 's'} to ${rc.model}` },
    ];
    const allOk = !offline && att.rows.every((r) => r.ok) && calls.every((c) => c.ok) && structure.every((r) => r.ok);
    return { ok: allOk, unreachable: att.rows.some((r) => !r.ok && r.unreachable), offline, att, code, calls, structure, tests: [], regressions: [], safe: null, reply: o.reply, sensitive, signed: { changes: [], kept: [] }, tokens: { original: null, optimized: null, savedPerCall: 0 } };
  }

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
  // Evidence and adoption are separate verdicts: a run can be fully verified and still unsafe to adopt.
  const regressions = results.map((t, i) => ({ i, t })).filter(({ t }) => t.original?.pass && !t.optimized?.pass);
  const allOk = !offline && att.rows.every((r) => r.ok) && calls.every((c) => c.ok) && structure.every((r) => r.ok);
  const unreachable = att.rows.some((r) => !r.ok && r.unreachable);
  return {
    ok: allOk, unreachable, offline, att, code, calls, structure, tests: results, regressions, safe: allOk && regressions.length === 0 && results.every((t) => t.optimized?.pass),
    signed: { changes: Array.isArray(signed.changes) ? signed.changes : [], kept: Array.isArray(signed.kept) ? signed.kept : [] },
    tokens: { original: results[0]?.original?.tokens ?? null, optimized: results[0]?.optimized?.tokens ?? null, savedPerCall: saved.length ? Math.round(saved.reduce((a, b) => a + b, 0) / saved.length) : 0 },
  };
}
