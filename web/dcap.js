/* Intel TDX quote (v4) signature chain, checked in the page with no verifier service:

   1. The quote (header + TD report) is signed by the quoting enclave's attestation key (ECDSA P-256).
   2. The quoting enclave's own report binds that key: report_data = sha256(attestation key || auth data).
   3. That report is signed by the platform's PCK certificate.
   4. PCK certificate -> PCK Platform/Processor CA -> Intel SGX Root CA, whose key is pinned below
      (the root Intel publishes at certificates.trustedservices.intel.com).
   5. The quoting enclave is Intel's TDX one (its MRSIGNER is Intel's).

   Not checked here: TCB status and revocation, which need Intel's collateral (TCB info, CRLs).
   Those still come from the DCAP verifier service. */
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
  const [, , issuer, validity, subject, spki] = f.slice(i);
  const [nb, na] = children(der, validity);
  const keyBits = children(der, spki)[1];
  const cn = (name) => { const s = new TextDecoder().decode(der.slice(name.start, name.end)); return (s.match(/Intel SGX [A-Za-z ]+?(?=[^A-Za-z ]|$)/) || [''])[0].trim(); };
  return {
    tbs: der.slice(tbs.from, tbs.end),
    issuer: der.slice(issuer.from, issuer.end), subject: der.slice(subject.from, subject.end), name: cn(subject),
    notBefore: time(der, nb), notAfter: time(der, na),
    key: der.slice(keyBits.start + 1, keyBits.end), // skip the unused-bits byte
    sig: derSigToCompact(der.slice(sigVal.start + 1, sigVal.end)),
  };
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
