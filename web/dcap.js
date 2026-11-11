/* Intel TDX quote (v4) signature chain, checked in the page with no verifier service:

   1. The quote (header + TD report) is signed by the quoting enclave's attestation key (ECDSA P-256).
   2. The quoting enclave's own report binds that key: report_data = sha256(attestation key || auth data).
   3. That report is signed by the platform's PCK certificate.
   4. PCK certificate -> PCK Platform/Processor CA -> Intel SGX Root CA, whose key is pinned below
      (the root Intel publishes at certificates.trustedservices.intel.com).
   5. The quoting enclave is Intel's TDX one (its MRSIGNER is Intel's).

   checkCollateral() then finishes the DCAP check, also in the page, with Intel's signed collateral:
   6. TCB info for the platform's FMSPC, signed by Intel's TCB Signing key (chained to the same pinned
      root): the platform's TCB level from the PCK certificate and the quote, and the TDX module's.
   7. TD quoting enclave identity, signed the same way: the QE's TCB level.
   8. PCK and root CRLs, signed by Intel: neither the PCK certificate nor its CA is revoked.
   The collateral is fetched through a plain pass-through (Intel's PCS sends no CORS headers); every
   piece carries Intel's signature, so the pass-through cannot alter it unnoticed. */
import { p256, sha256 } from './vendor/noble.js?v=14';

const INTEL_ROOT_KEY = '040ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394';
const INTEL_TDX_QE_MRSIGNER = 'dc9e2a7c6f948f17474e34a7fc43ed030f7c1563f1babddf6340c82e0e54a8c5';

const toHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => Uint8Array.from(String(h).replace(/^0x/i, '').match(/../g) || [], (x) => parseInt(x, 16));
const u16 = (b, o) => b[o] | (b[o + 1] << 8);
const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const verify = (sig64, data, pub) => { try { return p256.verify(sig64, sha256(data), pub); } catch { return false; } };

/* Minimal DER reading: enough for X.509 certificates with ECDSA P-256 keys. */
function tlv(b, o) {
  const tag = b[o]; let len = b[o + 1]; let start = o + 2;
  if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[o + 2 + i]; start += n; }
  return { tag, start, end: start + len, from: o };
}
function children(b, node) { const out = []; for (let o = node.start; o < node.end;) { const c = tlv(b, o); out.push(c); o = c.end; } return out; }
function derSigToCompact(b) {
  const seq = tlv(b, 0); const [r, s] = children(b, seq);
  const int32 = (n) => { let v = b.slice(n.start, n.end); while (v.length > 32 && v[0] === 0) v = v.slice(1); const out = new Uint8Array(32); out.set(v, 32 - v.length); return out; };
  const out = new Uint8Array(64); out.set(int32(r)); out.set(int32(s), 32); return out;
}
function time(b, n) {
  const t = new TextDecoder().decode(b.slice(n.start, n.end));
  const y = n.tag === 0x17 ? 2000 + Number(t.slice(0, 2)) - (Number(t.slice(0, 2)) >= 50 ? 100 : 0) : Number(t.slice(0, 4));
  const r = n.tag === 0x17 ? t.slice(2) : t.slice(4);
  return Date.UTC(y, Number(r.slice(0, 2)) - 1, Number(r.slice(2, 4)), Number(r.slice(4, 6)), Number(r.slice(6, 8)), Number(r.slice(8, 10)));
}
function parseCert(der) {
  const cert = tlv(der, 0); const [tbs, , sigVal] = children(der, cert);
  const f = children(der, tbs); const i = f[0].tag === 0xa0 ? 1 : 0;
  const [serial, , issuer, validity, subject, spki] = f.slice(i);
  const ext = f.slice(i).find((x) => x.tag === 0xa3);
  const [nb, na] = children(der, validity);
  const keyBits = children(der, spki)[1];
  const cn = (name) => { const s = new TextDecoder().decode(der.slice(name.start, name.end)); return (s.match(/Intel SGX [A-Za-z ]+?(?=[^A-Za-z ]|$)/) || [''])[0].trim(); };
  return {
    tbs: der.slice(tbs.from, tbs.end),
    issuer: der.slice(issuer.from, issuer.end), subject: der.slice(subject.from, subject.end), name: cn(subject),
    notBefore: time(der, nb), notAfter: time(der, na),
    key: der.slice(keyBits.start + 1, keyBits.end), // skip the unused-bits byte
    sig: derSigToCompact(der.slice(sigVal.start + 1, sigVal.end)),
    serial: intHex(der.slice(serial.start, serial.end)),
    sgx: ext ? sgxExtension(der, ext) : null,
  };
}
const intHex = (b) => toHex(b).replace(/^(00)+(?=..)/, '');
/* Intel's SGX extension (OID 1.2.840.113741.1.13.1) in a PCK certificate: FMSPC, PCE SVN and the 16 CPU SVN components. */
const SGX_OID = '2a864886f84d010d01';
function sgxExtension(der, extWrap) {
  for (const e of children(der, children(der, extWrap)[0])) {
    const [oid, val] = children(der, e).filter((x) => x.tag !== 0x01);
    if (toHex(der.slice(oid.start, oid.end)) !== SGX_OID) continue;
    const out = { fmspc: null, pcesvn: null, comps: [], ca: null };
    const walk = (node) => {
      for (const kv of children(der, node)) {
        const [k, v] = children(der, kv);
        const id = toHex(der.slice(k.start, k.end));
        if (!id.startsWith(SGX_OID)) continue;
        const sub = id.slice(SGX_OID.length);
        const num = () => der.slice(v.start, v.end).reduce((n, x) => n * 256 + x, 0);
        if (sub === '04') out.fmspc = toHex(der.slice(v.start, v.end)).toUpperCase();
        else if (sub === '02') walk(v);
        else if (sub.startsWith('02') && sub.length === 4) { const n = parseInt(sub.slice(2), 16); if (n <= 16) out.comps[n - 1] = num(); else if (n === 17) out.pcesvn = num(); }
      }
    };
    walk(tlv(der, val.start));
    return out;
  }
  return null;
}
/* A DER certificate revocation list: issuer, dates, revoked serials, and the signed part. */
function parseCrl(der) {
  const crl = tlv(der, 0); const [tbs, , sigVal] = children(der, crl);
  const f = children(der, tbs); let i = f[0].tag === 0x02 ? 1 : 0;
  const issuer = f[i + 1]; const thisUpdate = time(der, f[i + 2]); i += 3;
  let nextUpdate = null; if (f[i] && (f[i].tag === 0x17 || f[i].tag === 0x18)) { nextUpdate = time(der, f[i]); i++; }
  const revoked = f[i] && f[i].tag === 0x30 ? children(der, f[i]).map((r) => { const s = children(der, r)[0]; return intHex(der.slice(s.start, s.end)); }) : [];
  return { tbs: der.slice(tbs.from, tbs.end), issuer: der.slice(issuer.from, issuer.end), thisUpdate, nextUpdate, revoked, sig: derSigToCompact(der.slice(sigVal.start + 1, sigVal.end)) };
}
function pemCerts(text) {
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/g)]
    .map((m) => Uint8Array.from(atob(m[1].replace(/\s+/g, '')), (c) => c.charCodeAt(0)));
}

/** Check a TDX v4 quote's signature chain up to Intel's pinned root. `now` is for certificate validity. */
export function verifyTdxQuote(quoteHex, now = Date.now()) {
  const steps = { quoteSig: false, qeBinding: false, qeSig: false, chain: false, root: false, qeIdentity: false, validity: false };
  try {
    const q = fromHex(quoteHex);
    if (u16(q, 0) !== 4 || u32(q, 4) !== 0x81) return { ok: false, steps, error: 'not a TDX v4 quote' };
    const signed = q.slice(0, 632);
    const sd = q.slice(636, 636 + u32(q, 632));
    const quoteSig = sd.slice(0, 64); const attKey = sd.slice(64, 128);
    if (u16(sd, 128) !== 6) return { ok: false, steps, error: 'unexpected certification data type' };
    const qe = sd.slice(134, 134 + 384); const qeSig = sd.slice(518, 582);
    const authLen = u16(sd, 582); const auth = sd.slice(584, 584 + authLen);
    let o = 584 + authLen;
    if (u16(sd, o) !== 5) return { ok: false, steps, error: 'no PCK certificate chain in the quote' };
    const chainText = new TextDecoder().decode(sd.slice(o + 6, o + 6 + u32(sd, o + 2)));

    steps.quoteSig = verify(quoteSig, signed, Uint8Array.of(4, ...attKey));
    const qeReportData = qe.slice(320, 384);
    steps.qeBinding = eq(qeReportData.slice(0, 32), sha256(Uint8Array.of(...attKey, ...auth))) && qeReportData.slice(32).every((x) => x === 0);
    steps.qeIdentity = toHex(qe.slice(128, 160)) === INTEL_TDX_QE_MRSIGNER;

    const [pck, ca, root] = pemCerts(chainText).map(parseCert);
    steps.qeSig = !!pck && verify(qeSig, qe, pck.key);
    steps.chain = !!root && eq(pck.issuer, ca.subject) && eq(ca.issuer, root.subject) && eq(root.issuer, root.subject)
      && verify(pck.sig, pck.tbs, ca.key) && verify(ca.sig, ca.tbs, root.key) && verify(root.sig, root.tbs, root.key);
    steps.root = !!root && toHex(root.key) === INTEL_ROOT_KEY;
    steps.validity = [pck, ca, root].every((c) => c && c.notBefore <= now && now <= c.notAfter);
    return { ok: Object.values(steps).every(Boolean), steps, chain: [pck, ca, root].map((c) => c?.name), pckNotAfter: pck?.notAfter };
  } catch (e) {
    return { ok: false, steps, error: String(e.message || e) };
  }
}

/* ---- Intel collateral: TCB status, QE identity and revocation, checked here ---- */

const STATUS_OK = new Set(['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded']);
const RANK = ['UpToDate', 'SWHardeningNeeded', 'ConfigurationNeeded', 'ConfigurationAndSWHardeningNeeded', 'OutOfDate', 'OutOfDateConfigurationNeeded', 'Revoked'];
const worst = (...xs) => xs.reduce((a, b) => (RANK.indexOf(b) > RANK.indexOf(a) || RANK.indexOf(b) < 0 ? b : a));

/** A signed collateral document from the issuer chain Intel sends with it: signing cert -> pinned root. */
function signerFromChain(chainText, now) {
  const [signer, root] = pemCerts(decodeURIComponent(chainText || '')).map(parseCert);
  if (!signer || !root) throw new Error('missing issuer chain');
  if (toHex(root.key) !== INTEL_ROOT_KEY) throw new Error('issuer chain does not end at Intel\'s root');
  if (!eq(signer.issuer, root.subject) || !verify(signer.sig, signer.tbs, root.key)) throw new Error('signing certificate is not signed by Intel\'s root');
  if (!(signer.notBefore <= now && now <= signer.notAfter)) throw new Error('signing certificate expired');
  return signer;
}
/** Intel signs the exact JSON text of the inner object. */
function signedJson(text, field, chain, now) {
  const at = text.indexOf(`"${field}"`); const start = text.indexOf('{', at); const end = text.lastIndexOf(',"signature"');
  if (at < 0 || start < 0 || end < start) throw new Error(`no ${field}`);
  const sig = fromHex((text.slice(end).match(/"signature"\s*:\s*"([0-9a-fA-F]+)"/) || [])[1] || '');
  const body = new TextEncoder().encode(text.slice(start, end));
  const signer = signerFromChain(chain, now);
  if (sig.length !== 64 || !verify(sig, body, signer.key)) throw new Error(`${field} signature does not verify`);
  const doc = JSON.parse(text.slice(start, end));
  if (now > Date.parse(doc.nextUpdate)) throw new Error(`${field} is past its next update`);
  return doc;
}
function checkCrl(der, chain, issuerCert, now) {
  const crl = parseCrl(der);
  const issuer = issuerCert || signerFromChain(chain, now);
  const key = issuer.key;
  if (issuer.subject && !eq(crl.issuer, issuer.subject)) throw new Error('CRL is from another issuer');
  if (!verify(crl.sig, crl.tbs, key)) throw new Error('CRL signature does not verify');
  if (crl.nextUpdate && now > crl.nextUpdate) throw new Error('CRL is past its next update');
  return crl;
}
const levelFor = (levels, ok) => levels.find((l) => ok(l.tcb));

/**
 * Finish the DCAP check with Intel's signed collateral. `get(kind, arg)` returns { text | bytes, chain }:
 * kind is 'tcb' (arg: FMSPC), 'qe', 'pckcrl' (arg: 'platform' | 'processor') or 'rootcrl'.
 */
export async function checkCollateral(quoteHex, get, now = Date.now()) {
  const out = { ok: false, status: null, advisories: [], tcbDate: null, revoked: null, error: null };
  try {
    const q = fromHex(quoteHex);
    const base = verifyTdxQuote(quoteHex, now);
    if (!base.ok) throw new Error('the quote\'s own signature chain fails');
    const sd = q.slice(636, 636 + u32(q, 632));
    const qe = sd.slice(134, 134 + 384); const authLen = u16(sd, 582); const o = 584 + authLen;
    const [pck, ca] = pemCerts(new TextDecoder().decode(sd.slice(o + 6, o + 6 + u32(sd, o + 2)))).map(parseCert);
    if (!pck.sgx?.fmspc) throw new Error('no SGX extension in the PCK certificate');
    const caKind = /Processor/.test(ca.name) ? 'processor' : 'platform';

    const [tcbR, qeR, pckCrlR, rootCrlR] = await Promise.all([get('tcb', pck.sgx.fmspc), get('qe'), get('pckcrl', caKind), get('rootcrl')]);
    const tcb = signedJson(tcbR.text, 'tcbInfo', tcbR.chain, now);
    const qeId = signedJson(qeR.text, 'enclaveIdentity', qeR.chain, now);
    const pckCrl = checkCrl(pckCrlR.bytes, pckCrlR.chain, ca, now);
    const rootCrl = checkCrl(rootCrlR.bytes, null, { key: fromHex(INTEL_ROOT_KEY) }, now);
    out.revoked = pckCrl.revoked.includes(pck.serial) || rootCrl.revoked.includes(ca.serial);
    if (out.revoked) { out.status = 'Revoked'; throw new Error('the PCK certificate or its CA is revoked'); }
    if (tcb.id !== 'TDX' || String(tcb.fmspc).toUpperCase() !== pck.sgx.fmspc) throw new Error('TCB info is for another platform');

    // Platform TCB level: CPU SVN components and PCE SVN from the PCK certificate, TDX components from the quote.
    const teeTcbSvn = q.slice(48, 64);
    const tdxFrom = teeTcbSvn[1] > 0 ? 2 : 0;
    const level = levelFor(tcb.tcbLevels, (t) => t.sgxtcbcomponents.every((c, i) => (pck.sgx.comps[i] ?? 0) >= c.svn)
      && pck.sgx.pcesvn >= t.pcesvn && t.tdxtcbcomponents.every((c, i) => i < tdxFrom || teeTcbSvn[i] >= c.svn));
    if (!level) throw new Error('no TCB level matches this platform');

    // TDX module: its signer and attributes, and its own TCB level when the quote names a module version.
    const mod = tcb.tdxModule;
    const maskEq = (val, want, mask) => { const v = fromHex(val); const w = fromHex(want); const m = fromHex(mask); return v.every((x, i) => (x & m[i]) === (w[i] & m[i])); };
    if (mod && (toHex(q.slice(112, 160)).toUpperCase() !== mod.mrsigner.toUpperCase() || !maskEq(toHex(q.slice(160, 168)), mod.attributes, mod.attributesMask))) throw new Error('TDX module identity does not match');
    let modStatus = 'UpToDate';
    if (teeTcbSvn[1] > 0 && tcb.tdxModuleIdentities) {
      const id = `TDX_${teeTcbSvn[1].toString(16).padStart(2, '0').toUpperCase()}`;
      const ident = tcb.tdxModuleIdentities.find((x) => x.id === id);
      if (!ident) throw new Error(`no identity for TDX module ${id}`);
      const ml = levelFor(ident.tcbLevels, (t) => teeTcbSvn[0] >= t.isvsvn);
      modStatus = ml ? ml.tcbStatus : 'OutOfDate';
      if (ml?.advisoryIDs) out.advisories.push(...ml.advisoryIDs);
    }

    // The TD quoting enclave: Intel's signer and product, masked attributes, and its TCB level.
    const qeOk = toHex(qe.slice(128, 160)).toUpperCase() === qeId.mrsigner.toUpperCase() && u16(qe, 256) === qeId.isvprodid
      && maskEq(toHex(qe.slice(16, 20)), qeId.miscselect, qeId.miscselectMask) && maskEq(toHex(qe.slice(48, 64)), qeId.attributes, qeId.attributesMask);
    if (!qeOk) throw new Error('the quoting enclave does not match Intel\'s identity');
    const ql = levelFor(qeId.tcbLevels, (t) => u16(qe, 258) >= t.isvsvn);
    const qeStatus = ql ? ql.tcbStatus : 'OutOfDate';

    out.status = worst(level.tcbStatus, modStatus, qeStatus);
    out.advisories = [...new Set([...(level.advisoryIDs || []), ...out.advisories, ...(ql?.advisoryIDs || [])])];
    out.tcbDate = level.tcbDate; out.evaluation = tcb.tcbEvaluationDataNumber; out.fmspc = pck.sgx.fmspc;
    out.ok = STATUS_OK.has(out.status);
    if (!out.ok) out.error = `TCB status ${out.status}`;
  } catch (e) { out.error = out.error || String(e.message || e); out.unreachable = !!e.unreachable; }
  return out;
}
