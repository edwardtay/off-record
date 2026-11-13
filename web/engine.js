/* Off Record engine: sends a message privately to a NEAR AI Cloud enclave and checks
   every piece of evidence. Plain ES module with no imports, so the browser page and the
   Node scripts (verify-receipt.mjs, capture-sample.mjs) share the exact same checks.
   Hashing uses globalThis.crypto.subtle (browsers, Node 20+). Every chat call is end-to-end
   encrypted to the attested model key (e2ee.js), so NEAR AI's gateway relays only ciphertext.

   deps = {
     fetch,                          // fetch implementation
     pcsUrl(kind, arg),              // where to fetch Intel's signed collateral (TCB info, QE identity, CRLs)
     gpuUrl                          // NVIDIA NRAS endpoint
   }
*/

import { newClientKeys, encryptTo, openRequestField, decryptWith, verifyEd25519 } from './e2ee.js?v=14';
import { verifyTdxQuote, checkCollateral } from './dcap.js?v=18';

export const NEARAI = 'https://cloud-api.near.ai/v1';
const ALGO = 'ed25519';
export const DEFAULT_MODEL = 'Qwen/Qwen3.8-27B';
export const RECEIPT_VERSION = 3;

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

/* Intel's signed collateral, fetched once per kind and kept for 10 minutes. Every piece is checked
   against Intel's signature in checkCollateral, so where it was fetched from does not matter. */
const collateralCache = new Map();
function collateralGetter(deps) {
  return (kind, arg = '') => {
    const k = `${kind}:${arg}`; const hit = collateralCache.get(k);
    if (hit && Date.now() - hit.at < 600000) return hit.p;
    const p = (async () => {
      let r;
      try { r = await deps.fetch(deps.pcsUrl(kind, arg)); } catch (e) { throw Object.assign(new Error(`Intel's collateral service unreachable (${e.message || e})`), { unreachable: true }); }
      if (!r.ok) throw Object.assign(new Error(`Intel's collateral service answered HTTP ${r.status}`), { unreachable: r.status === 429 || r.status >= 500 });
      const chain = r.headers.get('tcb-info-issuer-chain') || r.headers.get('sgx-enclave-identity-issuer-chain') || r.headers.get('sgx-pck-crl-issuer-chain');
      return kind.endsWith('crl') ? { bytes: new Uint8Array(await r.arrayBuffer()), chain } : { text: await r.text(), chain };
    })();
    p.catch(() => collateralCache.delete(k));
    collateralCache.set(k, { at: Date.now(), p });
    return p;
  };
}
/** The full DCAP check of a TDX quote, in-process: signature chain plus Intel's TCB status and revocation lists. */
export const intelCheck = (quote, deps) => checkCollateral(strip0x(quote), collateralGetter(deps));

/** Intel's collateral and NVIDIA's NRAS, asked now. Results stored in a receipt are never trusted. */
export async function vendorChecks(m, deps) {
  const out = { tdx: null, gpu: null };
  const c = await intelCheck(m.intel_quote, deps);
  out.tdx = { verified: c.ok, unreachable: !!c.unreachable, status: c.status, evaluation: c.evaluation, advisories: c.advisories, error: c.ok ? null : c.error };
  try {
    const [j, jwks] = await Promise.all([postJson(deps, deps.gpuUrl, m.nvidia_payload), deps.fetch(deps.jwksUrl || NRAS_JWKS).then((r) => r.json())]);
    // Every token NVIDIA returns (the platform result and one per GPU) must carry NVIDIA's signature.
    const overall = Array.isArray(j) && Array.isArray(j[0]) ? await verifyNvidiaJwt(j[0][1], jwks) : { ok: false };
    const detached = j && j[1] && typeof j[1] === 'object' ? Object.entries(j[1]) : [];
    const gpuTokens = await Promise.all(detached.map(([, t]) => verifyNvidiaJwt(t, jwks)));
    const claims = overall.claims || {};
    // The per-GPU tokens must be the ones the overall result names: the same GPUs, each token's sha256
    // equal to its digest in `submods`, and each token carrying the overall token's nonce.
    const submods = claims.submods && typeof claims.submods === 'object' ? claims.submods : {};
    const digests = await Promise.all(detached.map(([, t]) => sha256Hex(String(t))));
    const bound = detached.length > 0 && Object.keys(submods).length === detached.length
      && detached.every(([name], i) => {
        const s = submods[name];
        return Array.isArray(s) && s[0] === 'DIGEST' && Array.isArray(s[1]) && s[1][0] === 'SHA-256' && String(s[1][1]).toLowerCase() === digests[i];
      })
      && gpuTokens.every((g) => typeof claims.eat_nonce === 'string' && g.claims?.eat_nonce === claims.eat_nonce);
    out.gpu = {
      verified: overall.ok && bound && gpuTokens.length > 0 && gpuTokens.every((g) => g.ok) && claims['x-nvidia-overall-att-result'] === true,
      bound,
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
  const dcap = m.intel_quote ? verifyTdxQuote(m.intel_quote) : { ok: false, steps: {} };
  const failedSteps = Object.entries(dcap.steps).filter(([, ok]) => !ok).map(([k]) => k);
  rows.push({ id: 'intel-sig', label: 'Intel\'s signature on the quote checks out, here', ok: dcap.ok, detail: dcap.ok ? `signed by Intel's TDX quoting enclave; PCK certificate chain to Intel's pinned root key, checked here with no verifier service` : `failed: ${failedSteps.join(', ') || dcap.error}` });
  const t = vendor?.tdx;
  rows.push({ id: 'intel', label: 'Intel lists the platform as trusted and not revoked', ok: !!t?.verified, unreachable: !!t?.unreachable, detail: t?.error || `TCB ${t?.status} (Intel TCB evaluation ${t?.evaluation})${t?.advisories?.length ? `, advisories ${t.advisories.join(', ')}` : ''}; PCK certificate and CA not revoked; quoting enclave matches Intel's identity. Intel-signed collateral, checked here` });
  rows.push({ id: 'nvidia', label: 'NVIDIA attests the GPUs', ok: !!vendor?.gpu?.verified && strip0x(vendor.gpu.nonce) === strip0x(nonce) && vendor.gpu.noDebug, unreachable: !!vendor?.gpu?.unreachable, detail: vendor?.gpu?.error || `${vendor?.gpu?.gpus || 0} GPU${vendor?.gpu?.gpus === 1 ? '' : 's'}, each token's NVIDIA signature checked here and bound to the overall result, this nonce, debug off, secure boot on` });
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
  const sig = verifyTdxQuote(cm.quote || '').ok;
  return {
    ok: hash === strip0x(cm.actions_hash) && rd === hash + strip0x(nonce) && sameVm && sig, sig,
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
  const sig = verifyTdxQuote(g.intel_quote).ok;
  return { ok: key.length === 64 && rd === key + strip0x(nonce) && app.ok && app.debug === false && compose.ok && sig, sig, present: true, key, app, compose, quote: g.intel_quote };
}

/** All three, with Intel asked now about the deploy-log quote and the gateway quote. */
export async function codeChecks(report, nonce, model, deps, { offline = false } = {}) {
  const m = modelAttestation(report, model);
  const [compose, deploy, gateway] = await Promise.all([composeCheck(m), deployLog(m, nonce, model), gatewayCheck(report, nonce)]);
  const intel = async (q) => {
    if (offline || !q) return null;
    const c = await intelCheck(q, deps);
    return c.ok ? true : c.unreachable ? null : false;
  };
  [deploy.intel, gateway.intel, deploy.source] = await Promise.all([intel(deploy.quote), intel(gateway.quote), offline ? null : deployFile(deploy.containers?.[0], model, deps)]);
  delete deploy.quote; delete gateway.quote;
  return { compose, deploy, gateway };
}

const encHeaders = (key, client, modelPub) => ({ authorization: `Bearer ${key}`, 'content-type': 'application/json', 'x-signing-algo': ALGO, 'x-client-pub-key': client.publicHex, 'x-model-pub-key': modelPub, 'x-encryption-version': '2', 'x-no-aliasing': 'true' });
function sealMessages(modelPub, messages) { return messages.map((m) => ({ role: m.role, ...encryptTo(modelPub, m.content) })); }
/* With no key of their own, visitors send through prompt20.com's demo relay, which adds a demo key.
   The relay only takes encrypted requests, so it carries the same ciphertext NEAR AI's gateway sees. */
const apiBase = (deps) => deps.api || NEARAI;
async function nearError(r) {
  const t = await r.text().catch(() => '');
  let msg = t.slice(0, 200); let relay = false;
  try { const e = JSON.parse(t).error; msg = e?.message || msg; relay = !!e?.relay; } catch { /* raw */ }
  if (relay) return new Error(msg);
  if (r.status === 401 || r.status === 403) return new Error('NEAR AI refused the key. Check it at cloud.near.ai.');
  if (r.status === 402) return new Error('Your NEAR AI credits have run out. Top up at cloud.near.ai.');
  if (r.status === 429) return new Error('NEAR AI is rate limiting this key. Wait a moment and send again.');
  return new Error(`NEAR AI ${r.status}: ${msg}`);
}
/* The signature is stored a moment after the reply returns, so a 404 is retried. */
async function fetchSignature(key, model, id, deps) {
  let signature = { error: 'signature not fetched' };
  for (let a = 0; a < 6; a++) {
    if (a) await new Promise((res) => setTimeout(res, 800 * a));
    const sr = await deps.fetch(`${apiBase(deps)}/signature/${encodeURIComponent(id)}?model=${encodeURIComponent(model)}&signing_algo=${ALGO}`, { headers: { authorization: `Bearer ${key}` } });
    if (sr.ok) { signature = await sr.json(); break; }
    signature = { error: `signature HTTP ${sr.status}` };
    if (sr.status !== 404) break;
  }
  return signature;
}

/**
 * One encrypted, signed call. Message contents are encrypted to `modelPub` (the key in the quote); the
 * reply comes back encrypted to a one-time client key. The receipt keeps the one-time secrets
 * ("openings") so a checker can confirm each field opens only with the attested key.
 */
export async function chat({ key, model, modelPub, messages, maxTokens = 1500 }, deps) {
  const client = newClientKeys();
  const sealed = sealMessages(modelPub, messages);
  const request = JSON.stringify({ model, messages: sealed.map((m) => ({ role: m.role, content: m.hex })), temperature: 0, max_tokens: maxTokens, reasoning_effort: 'low' });
  const r = await deps.fetch(`${apiBase(deps)}/chat/completions`, { method: 'POST', body: request, headers: encHeaders(key, client, modelPub) });
  if (!r.ok) throw await nearError(r);
  const response = await r.text();
  const j = JSON.parse(response);
  return { id: j.id, request, response, signature: await fetchSignature(key, model, j.id, deps), e2ee: { client: client.x25519Secret, openings: sealed.map((m) => m.opening) } };
}

/**
 * The same, streamed: each encrypted delta is decrypted as it arrives and passed to onDelta. The
 * exact event-stream bytes are kept, because the signature covers sha256 of the whole stream.
 * A stopped stream has no signature and is marked as such.
 */
export async function chatStream({ key, model, modelPub, messages, maxTokens = 4000, onDelta = () => {}, signal }, deps) {
  const client = newClientKeys();
  const sealed = sealMessages(modelPub, messages);
  // No hidden reasoning: the answer starts sooner and the stream (kept whole for the signature) is
  // about half the size. A model that refuses 'none' gets 'low' (a 400 is answered before any work).
  const body = (effort) => JSON.stringify({ model, messages: sealed.map((m) => ({ role: m.role, content: m.hex })), stream: true, max_tokens: maxTokens, reasoning_effort: effort });
  let request = body('none');
  let r = await deps.fetch(`${apiBase(deps)}/chat/completions`, { method: 'POST', body: request, headers: encHeaders(key, client, modelPub), signal });
  if (r.status === 400) { request = body('low'); r = await deps.fetch(`${apiBase(deps)}/chat/completions`, { method: 'POST', body: request, headers: encHeaders(key, client, modelPub), signal }); }
  if (!r.ok) throw await nearError(r);
  const reader = r.body.getReader(); const dec = new TextDecoder();
  let response = ''; let pending = ''; let id = null; let stopped = false;
  const take = (line) => {
    if (!line.startsWith('data: ') || line === 'data: [DONE]') return;
    const j = parse(line.slice(6)); if (!j) return;
    id = id || j.id;
    const c = j.choices?.[0]?.delta?.content;
    if (c) { try { onDelta(decryptWith(client.x25519Secret, c)); } catch { /* checked again when the call is opened */ } }
  };
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const t = dec.decode(value, { stream: true }); response += t; pending += t;
      const lines = pending.split('\n'); pending = lines.pop();
      lines.forEach(take);
    }
  } catch (e) { if (e.name === 'AbortError' || signal?.aborted) stopped = true; else throw e; }
  response += dec.decode(); take(pending);
  const signature = stopped || !id ? { error: stopped ? 'stopped before the end' : 'no reply id' } : await fetchSignature(key, model, id, deps);
  return { id, request, response, signature, stopped, e2ee: { client: client.x25519Secret, openings: sealed.map((m) => m.opening) } };
}

const parse = (s) => { try { return JSON.parse(s); } catch { return null; } };

/**
 * The plaintext of a call. For an encrypted call, every request field is opened with its one-time
 * secret against the attested model key, and the reply is decrypted with the client key; any
 * failure marks the call as not end-to-end encrypted to that key.
 */
/** The reply's encrypted content pieces and token usage, from a JSON reply or an event stream. */
function replyParts(text) {
  if (/^data: /.test(String(text || ''))) {
    const chunks = String(text).split('\n').filter((l) => l.startsWith('data: ') && l !== 'data: [DONE]').map((l) => parse(l.slice(6))).filter(Boolean);
    return { pieces: chunks.map((c) => c.choices?.[0]?.delta?.content).filter(Boolean), usage: chunks.find((c) => c.usage)?.usage || {}, model: chunks[0]?.model };
  }
  const j = parse(text) || {}; const c = j.choices?.[0]?.message?.content;
  return { pieces: c ? [c] : [], usage: j.usage || {}, model: j.model };
}
export const callUsage = (call) => replyParts(call?.response).usage;
export function openCall(call, modelPub) {
  const req = parse(call?.request) || {};
  const { pieces, usage } = replyParts(call?.response);
  if (!call?.e2ee) return { e2ee: false, model: req.model, messages: req.messages || [], reply: pieces.join('').trim(), tokens: usage.prompt_tokens ?? null };
  try {
    const messages = (req.messages || []).map((m, i) => ({ role: m.role, content: openRequestField(modelPub, call.e2ee.openings[i], m.content) }));
    if (messages.length !== (call.e2ee.openings || []).length) throw new Error('openings do not match the messages');
    const reply = pieces.map((p) => decryptWith(call.e2ee.client, p)).join('').trim();
    return { e2ee: true, model: req.model, messages, reply, tokens: usage.prompt_tokens ?? null };
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

/**
 * Start a verified session: a fresh attestation, checked before anything is sent. Needs no API key.
 * Every later turn is encrypted to the key this attestation names, and every reply must be signed by it.
 */
export async function openSession({ model = DEFAULT_MODEL, onStep = () => {} }, deps) {
  const nonce = newNonce();
  onStep('attest', 'Asking NEAR AI for a fresh hardware attestation');
  const report = await fetchAttestation(model, nonce, deps);
  if (report.error) throw new Error(/external provider/i.test(report.error) ? `Refused before sending: NEAR AI runs ${model} at an outside provider, not in its own TEE. Nothing was sent.` : `Attestation failed, nothing was sent: ${report.error}`);
  if (privacyKind(report) !== 'model-tee') throw new Error(`${model} does not run in its own TEE on NEAR AI Cloud. Nothing was sent.`);
  onStep('vendor', 'Checking the quote with Intel and the GPUs with NVIDIA');
  const att = await checkAttestation(report, nonce, model, await vendorChecks(modelAttestation(report, model), deps));
  const bad = att.rows.filter((r) => !r.ok);
  if (bad.length) throw new Error(`Nothing was sent: the enclave did not pass "${bad[0].label}" (${bad[0].detail}).`);
  if (!att.ed) throw new Error('NEAR AI did not return an Ed25519 key for this model, so messages cannot be encrypted to it. Nothing was sent.');
  return { model, nonce, attestation: report, att, signer: att.signer, at: Date.now() };
}

/** A new, empty receipt for a session. Turns are appended as they are sent. */
export const newReceipt = (session, system = '') => ({ version: RECEIPT_VERSION, kind: 'chat', tool: 'https://prompt20.com/tools/off-record/', created: new Date().toISOString(), model: session.model, nonce: session.nonce, attestation: session.attestation, system, turns: [], calls: [] });

/** The messages turn i sends: the instructions, every earlier turn with its signed reply, then this message. */
export function turnMessages(system, turns, replies, i) {
  const out = String(system || '').trim() ? [{ role: 'system', content: system }] : [];
  for (let j = 0; j < i; j++) out.push({ role: 'user', content: turns[j] }, { role: 'assistant', content: replies[j] ?? '' });
  out.push({ role: 'user', content: turns[i] });
  return out;
}

/**
 * Send one turn of a chat, appended to the receipt. The reply streams through onDelta; in parallel a
 * second encrypted call asks the enclave to list the sensitive items in this message.
 * `replies` are the verified replies of the earlier turns, as shown.
 */
export async function sendTurn({ key, session, rc, replies, message, onDelta, signal, scan = true }, deps) {
  const i = rc.turns.length;
  const turns = [...rc.turns, message];
  const messages = turnMessages(rc.system, turns, replies, i);
  const [call, scanCall] = await Promise.all([
    chatStream({ key, model: rc.model, modelPub: session.signer, messages, onDelta, signal }, deps),
    scan ? chat({ key, model: rc.model, modelPub: session.signer, maxTokens: 2000, messages: [{ role: 'system', content: SCAN_SYSTEM }, { role: 'user', content: message }] }, deps).catch(() => null) : null,
  ]);
  rc.turns.push(message);
  rc.calls.push({ ...call, role: `turn-${i}` });
  if (scanCall) rc.calls.push({ ...scanCall, role: `scan-${i}` });
  return rc;
}

/** Kept for the command line: one private question, as a one-turn chat. */
export async function runAsk({ key, model = DEFAULT_MODEL, system = '', message, onStep = () => {} }, deps) {
  const session = await openSession({ model, onStep }, deps);
  onStep('send', 'Sending your message, encrypted to the enclave key');
  return sendTurn({ key, session, rc: newReceipt(session, system), replies: [], message }, deps);
}

/* A one-question receipt from before chats ("ask") reads as a one-turn chat. */
function asChat(rc) {
  if (rc.kind === 'chat') return rc;
  if (rc.kind === 'ask') return { ...rc, kind: 'chat', turns: [rc.message], calls: rc.calls.map((c) => ({ ...c, role: { ask: 'turn-0', scan: 'scan-0' }[c.role] || c.role })) };
  throw new Error('This receipt is from the retired prompt-shortening mode. This version checks private chats only.');
}

/**
 * Check every turn against the signer: each call is signed over its exact bytes and encrypted to the
 * attested key; turn i sent exactly the instructions, the earlier turns and their signed replies, and
 * this message; each scan sent only this message. No network except the signature hashes.
 */
export async function checkTurns(rc0, signer, deps) {
  const rc = asChat(rc0);
  const calls = await Promise.all(rc.calls.map(async (c) => ({ role: c.role, id: c.id, stopped: !!c.stopped, ...(await checkCall(c, signer, deps)) })));
  const roles = rc.calls.map((c) => c.role);
  const n = rc.turns.length;
  const allowed = new Set(rc.turns.flatMap((_, i) => [`turn-${i}`, `scan-${i}`]));
  const shapeOk = n > 0 && roles.every((r) => allowed.has(r)) && new Set(roles).size === roles.length && rc.turns.every((_, i) => roles.includes(`turn-${i}`));
  const replies = []; const perTurn = []; let e2ee = rc.calls.length > 0;
  for (let i = 0; i < n; i++) {
    const call = rc.calls.find((c) => c.role === `turn-${i}`);
    const o = call ? openCall(call, signer) : { e2ee: false, messages: [] };
    const want = turnMessages(rc.system, rc.turns, replies, i);
    const sentOk = !!call && o.model === rc.model && o.messages.length === want.length && o.messages.every((m, k) => m.role === want[k].role && m.content === want[k].content);
    const sc = rc.calls.find((c) => c.role === `scan-${i}`);
    const so = sc ? openCall(sc, signer) : null;
    const scanOk = !sc || (so.e2ee && so.model === rc.model && so.messages.length === 2 && so.messages[1].content === rc.turns[i]);
    e2ee = e2ee && !!o.e2ee && (!so || so.e2ee);
    const sig = calls.find((c) => c.role === `turn-${i}`);
    replies.push(o.reply);
    perTurn.push({ reply: o.reply, sentOk, scanOk, e2ee: !!o.e2ee && (!so || so.e2ee), signed: !!sig?.ok, stopped: !!call?.stopped, sensitive: so && scanOk ? parseScan(so.reply, rc.turns[i]) : null, ok: sentOk && scanOk && !!o.e2ee && !!sig?.ok });
  }
  const structure = [
    { id: 'e2ee', label: 'Every message was encrypted to the attested key', ok: e2ee, detail: `${rc.calls.length} call${rc.calls.length === 1 ? '' : 's'}: every field opens only with the key in the quote; replies only with each call's one-time key` },
    { id: 'ask', label: 'The chat shown is the one signed', ok: shapeOk && perTurn.every((t) => t.sentOk && t.scanOk), detail: `${n} turn${n === 1 ? '' : 's'}: each sent exactly the earlier turns and their signed replies, to ${rc.model}` },
  ];
  const sensitive = perTurn.some((t) => t.sensitive) ? perTurn.flatMap((t) => t.sensitive || []) : null;
  return { rc, calls, structure, perTurn, replies, sensitive };
}

/**
 * Check a receipt from scratch. Vendor verdicts are always fetched now, never read from the receipt.
 * `offline` skips the network: the verdict can then never be VERIFIED.
 */
export async function verifyReceipt(rc0, deps, { offline = false } = {}) {
  const rc = asChat(rc0);
  const m = modelAttestation(rc.attestation, rc.model);
  const [vendor, live, code] = await Promise.all(offline ? [null, null, codeChecks(rc.attestation, rc.nonce, rc.model, deps, { offline })] : [vendorChecks(m, deps), liveApp(rc.model, deps), codeChecks(rc.attestation, rc.nonce, rc.model, deps)]);
  const att = await checkAttestation(rc.attestation, rc.nonce, rc.model, vendor, live);
  if (offline) att.rows.filter((r) => r.id === 'intel' || r.id === 'nvidia').forEach((r) => { r.detail = 'not checked (offline)'; });
  const t = await checkTurns(rc, att.signer, deps);
  // Verified covers the hardware proof (including the measured compose file), the key, the encryption, every
  // signature and the conversation. The deploy log, GitHub file and gateway are shown separately.
  const allOk = !offline && att.rows.every((r) => r.ok) && code.compose.ok && t.calls.every((c) => c.ok) && t.structure.every((r) => r.ok);
  return { ok: allOk, unreachable: att.rows.some((r) => !r.ok && r.unreachable), offline, att, code, calls: t.calls, structure: t.structure, perTurn: t.perTurn, replies: t.replies, reply: t.replies[t.replies.length - 1], sensitive: t.sensitive, rc: t.rc };
}
