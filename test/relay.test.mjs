// The free demo relay (nginx njs), run here with a stand-in for nginx's request object and shared store.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import relay from '../nginx/off-record-relay.js';

// A throwaway demo key, so the counting runs as it does in nginx.
process.env.OFFRECORD_KEY_FILE = join(mkdtempSync(join(tmpdir(), 'or-')), 'k');
writeFileSync(process.env.OFFRECORD_KEY_FILE, 'test-key');

const SEALED = 'ab'.repeat(90);
const good = () => ({ model: 'Qwen/Qwen3.8-27B', messages: [{ role: 'user', content: SEALED }], stream: true, max_tokens: 4000, reasoning_effort: 'none' });

test('the request the page sends passes', () => assert.equal(relay.shapeError(good()), ''));

test('plaintext, unknown fields, other models and odd sizes are refused', () => {
  const cases = {
    plaintext: (b) => { b.messages[0].content = 'my blood test says'; },
    'short hex': (b) => { b.messages[0].content = 'abcd'; },
    'extra field': (b) => { b.n = 999; },
    'extra message field': (b) => { b.messages[0].name = 'x'; },
    'outside model': (b) => { b.model = 'anthropic/claude-fable-5'; },
    'fractional tokens': (b) => { b.max_tokens = 10.5; },
    'too many tokens': (b) => { b.max_tokens = 4001; },
    'high effort': (b) => { b.reasoning_effort = 'high'; },
    'no messages': (b) => { b.messages = []; },
    'bad role': (b) => { b.messages[0].role = 'tool'; },
  };
  for (const [name, change] of Object.entries(cases)) {
    const b = good(); change(b);
    assert.notEqual(relay.shapeError(b), '', name);
  }
});

function stand(ip, body = good()) {
  const out = {};
  return {
    out,
    headersIn: { 'X-Encryption-Version': '2', 'X-Client-Pub-Key': 'a'.repeat(64), 'X-Model-Pub-Key': 'b'.repeat(64), 'CF-Connecting-IP': ip },
    headersOut: {},
    remoteAddress: ip,
    requestText: JSON.stringify(body),
    return(status, text) { out.status = status; out.text = text; },
    internalRedirect(to) { out.status = 200; out.to = to; },
  };
}

test('a visitor past the limit cannot use up everyone\'s allowance', () => {
  const store = new Map();
  globalThis.ngx = { shared: { offrecord: { get: (k) => store.get(k), incr: (k, d, init) => { const v = (store.has(k) ? store.get(k) : init) + d; store.set(k, v); return v; } } } };
  const day = new Date().toISOString().slice(0, 10);
  assert.ok(relay.auth());
  for (let i = 0; i < 40; i++) { const r = stand('1.2.3.4'); relay.chat(r); assert.equal(r.out.status, 200); }
  for (let i = 0; i < 100; i++) { const r = stand('1.2.3.4'); relay.chat(r); assert.equal(r.out.status, 429); }
  assert.equal(store.get(`all:${day}`), 40, 'refused calls do not count toward the shared allowance');
  const other = stand('5.6.7.8'); relay.chat(other); assert.equal(other.out.status, 200);
});
