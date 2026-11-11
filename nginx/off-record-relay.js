// Off Record demo relay (njs). Visitors without a NEAR AI key send through prompt20.com, which adds a
// demo key. The relay only accepts end-to-end encrypted requests (checked field by field below) to the listed private models, caps the
// reply size, and counts calls per visitor and in total for each UTC day, so the demo credit cannot be
// spent on other models or drained by one visitor.
//
// What it keeps: nothing from a request body, and no IP address. The daily counter is keyed by a
// keyed hash of the visitor's IP and the date, so it cannot be turned back into an IP, and every entry
// expires within two days. These locations write no access log (see nginx/off-record.conf).
import fs from 'fs';
import crypto from 'crypto';

const MODELS = [
  'Qwen/Qwen3.8-27B', 'Qwen/Qwen3.6-35B-A3B-FP8', 'Qwen/Qwen3-VL-30B-A3B-Instruct',
  'deepseek-ai/DeepSeek-V4.1-Flash-1017', 'z-ai/glm-5.3-flash',
  'Qwen/Qwen3.8-27B-abliterated', 'deepseek-ai/DeepSeek-V4.1-Flash-1017-abliterated',
];
// Each message is two calls: the reply and the sensitive-item scan.
const PER_VISITOR = 40;
const PER_DAY = 1500;
const MAX_TOKENS = 4000;

let key = null;
function auth() {
  if (key === null) {
    try { key = fs.readFileSync(process.env.OFFRECORD_KEY_FILE || '/etc/nginx/secrets/near-ai.key', 'utf8').trim(); } catch (e) { key = ''; }
  }
  return key ? `Bearer ${key}` : '';
}

function refuse(r, status, message) {
  r.headersOut['Content-Type'] = 'application/json';
  r.return(status, JSON.stringify({ error: { message, relay: true } }));
}

function visitor(r, day) {
  const ip = r.headersIn['CF-Connecting-IP'] || r.remoteAddress;
  return crypto.createHmac('sha256', key).update(`${day}|${ip}`).digest('hex').slice(0, 24);
}

// The request body the page sends, and nothing else. Every message content must be ciphertext in
// NEAR AI's E2EE v2 layout: hex of a 32-byte one-time public key, a 24-byte nonce, then the sealed text
// with its 16-byte tag. So a plaintext message is refused here, before it costs anything.
const FIELDS = ['model', 'messages', 'stream', 'max_tokens', 'temperature', 'reasoning_effort'];
const ROLES = ['system', 'user', 'assistant'];
const SEALED = /^(?:[0-9a-f]{2}){72,}$/;
function shapeError(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return 'The demo relay could not read this request.';
  const keys = Object.keys(body);
  for (let i = 0; i < keys.length; i++) if (FIELDS.indexOf(keys[i]) < 0) return `The demo relay does not pass the field "${keys[i]}".`;
  if (MODELS.indexOf(body.model) < 0) return 'The free demo covers the private models in the list. Add your own NEAR AI key for others.';
  if (!Number.isInteger(body.max_tokens) || body.max_tokens < 1 || body.max_tokens > MAX_TOKENS) return 'The demo relay caps replies at 4,000 tokens.';
  if (body.stream !== undefined && typeof body.stream !== 'boolean') return 'The demo relay could not read this request.';
  if (body.reasoning_effort !== undefined && ['none', 'low'].indexOf(body.reasoning_effort) < 0) return 'The demo relay only allows low reasoning effort.';
  if (body.temperature !== undefined && typeof body.temperature !== 'number') return 'The demo relay could not read this request.';
  const m = body.messages;
  if (!Array.isArray(m) || !m.length || m.length > 200) return 'The demo relay could not read this request.';
  for (let i = 0; i < m.length; i++) {
    const x = m[i];
    if (!x || ROLES.indexOf(x.role) < 0 || Object.keys(x).length !== 2) return 'The demo relay could not read this request.';
    if (typeof x.content !== 'string' || !SEALED.test(x.content)) return 'The demo relay only carries end-to-end encrypted requests.';
  }
  return '';
}

function chat(r) {
  if (!auth()) return refuse(r, 503, 'The free demo is off right now. Add your own NEAR AI key under Key and model.');
  const h = r.headersIn;
  if (h['X-Encryption-Version'] !== '2' || !/^[0-9a-f]{64}$/.test(h['X-Client-Pub-Key'] || '') || !/^[0-9a-f]{64}$/.test(h['X-Model-Pub-Key'] || '')) {
    return refuse(r, 400, 'The demo relay only carries end-to-end encrypted requests.');
  }
  let body;
  try { body = JSON.parse(r.requestText); } catch (e) { return refuse(r, 400, 'The demo relay could not read this request.'); }
  const bad = shapeError(body);
  if (bad) return refuse(r, /private models/.test(bad) ? 403 : 400, bad);
  // The visitor's own count comes first, so a visitor past their limit cannot use up everyone's allowance.
  const day = new Date().toISOString().slice(0, 10);
  const d = ngx.shared.offrecord;
  const mine = `v:${visitor(r, day)}`;
  if ((d.get(mine) || 0) >= PER_VISITOR) return refuse(r, 429, 'You have used today\'s free demo messages. Add your own NEAR AI key under Key and model to keep going.');
  if ((d.get(`all:${day}`) || 0) >= PER_DAY) return refuse(r, 429, 'The free demo has used today\'s allowance. Add your own NEAR AI key under Key and model, or come back tomorrow.');
  d.incr(mine, 1, 0); d.incr(`all:${day}`, 1, 0);
  r.internalRedirect('@offrecord_near');
}

function signature(r) {
  if (!auth()) return refuse(r, 503, 'The free demo is off right now.');
  r.internalRedirect('@offrecord_near');
}

export default { auth, chat, signature, shapeError };
