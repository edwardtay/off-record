/* Private Prompt Lab page. All checks live in engine.js, shared with the Node verifier.
   Imports carry the release tag so a deploy never mixes a cached old module with new ones. */
import { runLab, runAsk, verifyReceipt, fetchAttestation, privacyKind, newNonce, modelAttestation, NEARAI, DEFAULT_MODEL } from './engine.js?v=14';
import { SAMPLE_PROMPT, SAMPLE_TESTS, SAMPLE_ASK } from './sample.js?v=14';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = (n) => (n == null || Number.isNaN(n) ? 'n/a' : Number(n).toLocaleString('en-US'));
const money = (n) => (n >= 100 ? `$${Math.round(n).toLocaleString('en-US')}` : `$${n.toFixed(2)}`);

const deps = {
  fetch: (...a) => window.fetch(...a),
  // Intel's and NVIDIA's verifiers send no CORS headers, so prompt20.com passes the public evidence through.
  tdxUrl: new URL('verify/tdx', location.href).href,
  gpuUrl: new URL('verify/gpu', location.href).href,
};

/* Tabs */
const tabs = ['run', 'check', 'models'];
function showTab(t) {
  for (const x of tabs) { $(`tab-${x}`).setAttribute('aria-selected', String(x === t)); $(`tab-${x}`).tabIndex = x === t ? 0 : -1; $(`p-${x}`).hidden = x !== t; }
  $('stage-run').hidden = t === 'models'; $('stage-models').hidden = t !== 'models';
  if (t === 'models' && !scanned) scan();
}
for (const t of tabs) $(`tab-${t}`).addEventListener('click', () => showTab(t));
const TAB_ORDER = ['check', 'run', 'models'];
for (const t of TAB_ORDER) $(`tab-${t}`).addEventListener('keydown', (e) => {
  if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
  const next = TAB_ORDER[(TAB_ORDER.indexOf(t) + (e.key === 'ArrowRight' ? 1 : TAB_ORDER.length - 1)) % TAB_ORDER.length];
  showTab(next); $(`tab-${next}`).focus(); e.preventDefault();
});

/* Presets: ask privately, or optimise a prompt privately */
let preset = 'ask';
function setPreset(p) {
  preset = p;
  $('pre-ask').setAttribute('aria-pressed', String(p === 'ask')); $('pre-opt').setAttribute('aria-pressed', String(p === 'opt'));
  $('ask-fields').hidden = p !== 'ask'; $('opt-fields').hidden = p !== 'opt';
  $('run-label').textContent = p === 'ask' ? 'Send privately' : 'Optimise privately';
}
$('pre-ask').addEventListener('click', () => setPreset('ask'));
$('pre-opt').addEventListener('click', () => setPreset('opt'));

/* Inputs */
function promptCount() { const w = $('prompt').value.trim().split(/\s+/).filter(Boolean).length; $('prompt-count').textContent = w ? `${fmt(w)} words` : ''; }
$('prompt').addEventListener('input', promptCount);
function testRow(t = { input: '', must: [], mustNot: [] }) {
  const d = document.createElement('div');
  d.className = 'test';
  d.innerHTML = `<textarea rows="2" aria-label="Test message" placeholder="A message a user might send">${esc(t.input)}</textarea>
    <label>Reply must include<input type="text" class="must" value="${esc((t.must || []).join(', '))}" placeholder="30 days | 30-day, - Nova"></label>
    <label>Reply must not include<input type="text" class="mustnot" value="${esc((t.mustNot || []).join(', '))}"></label>
    <button type="button" class="btn ghost rm" aria-label="Remove this test case">Remove</button>`;
  d.querySelector('.rm').addEventListener('click', () => { d.remove(); testCount(); });
  $('tests').append(d); testCount();
}
function testCount() { $('test-count').textContent = `(${$('tests').children.length})`; }
const split = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
const readTests = () => [...$('tests').children].map((d) => ({ input: d.querySelector('textarea').value.trim(), must: split(d.querySelector('.must').value), mustNot: split(d.querySelector('.mustnot').value) })).filter((t) => t.input);
function loadSample() { $('prompt').value = SAMPLE_PROMPT; $('tests').innerHTML = ''; SAMPLE_TESTS.forEach(testRow); promptCount(); }
function loadAsk() { $('ask-system').value = SAMPLE_ASK.system; $('ask-message').value = SAMPLE_ASK.message; }
$('load-sample').addEventListener('click', loadSample);
$('load-ask').addEventListener('click', loadAsk);
$('add-test').addEventListener('click', () => testRow());
loadSample(); loadAsk();

/* Deploy-model prices from data.prompt20.com, for the optimisation preset */
let prices = [];
async function loadPrices() {
  for (let i = 0; i < 50 && !window.P20Models; i++) await new Promise((r) => setTimeout(r, 100));
  try {
    const { models } = await window.P20Models.loadAll(['reasoning-models', 'code-models', 'agents-models']);
    const seen = new Map();
    for (const m of models) if (m.inPrice > 0 && !seen.has(m.name)) seen.set(m.name, m);
    prices = [...seen.values()].sort((a, b) => a.name.localeCompare(b.name));
  } catch { prices = []; }
  const sel = $('deploy');
  if (!prices.length) { sel.innerHTML = '<option value="">Prices unavailable</option>'; return; }
  sel.innerHTML = prices.map((m, i) => `<option value="${i}">${esc(m.name)} ($${m.inPrice} per 1M input)</option>`).join('');
  const son = prices.map((m, i) => [m, i]).filter(([m]) => /claude sonnet/i.test(m.name)).sort((a, b) => String(b[0].released || '').localeCompare(String(a[0].released || '')));
  sel.value = String(son.length ? son[0][1] : 0);
  if (current) render(current.rc, current.v, current.note);
}
loadPrices();
$('deploy').addEventListener('change', () => current && render(current.rc, current.v, current.note));
$('calls').addEventListener('input', () => current && render(current.rc, current.v, current.note));

/* Private models scan */
let scanned = false;
const KIND = {
  'model-tee': ['ok', 'Private', 'Runs in its own TEE, with its own key'],
  'routed-tee': ['mid', 'Routed', 'Served by an attested router to another enclave'],
  'gateway-only': ['mid', 'Gateway only', 'Only the gateway is attested'],
  external: ['bad', 'Not private', 'Passed to an outside provider'],
  unknown: ['mid', 'Unknown', 'Could not check right now'],
};
async function scan() {
  scanned = true;
  $('scan').disabled = true; $('scan-sum').textContent = 'Checking';
  try {
    const list = (await (await fetch(`${NEARAI}/models`)).json()).data.map((m) => m.id);
    const nonce = newNonce(); const rows = []; let i = 0;
    await Promise.all(Array.from({ length: 8 }, async () => {
      while (i < list.length) {
        const id = list[i++];
        const r = await fetchAttestation(id, nonce, deps).catch((e) => ({ error: String(e) }));
        rows.push({ id, kind: privacyKind(r), detail: r.error ? r.error.replace(/^.*?: /, '').slice(0, 160) : ((r.model_attestations || [])[0]?.info?.app_name || (r.model_attestations || [])[0]?.provider || '') });
        $('scan-sum').textContent = `Checked ${rows.length} of ${list.length}`;
      }
    }));
    const order = Object.keys(KIND);
    rows.sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || a.id.localeCompare(b.id));
    $('models-t').tBodies[0].innerHTML = rows.map((r) => { const [c, l, d] = KIND[r.kind]; return `<tr><td>${esc(r.id)}</td><td><span class="pill ${c}">${l}</span></td><td>${esc(d)}${r.detail ? `. ${esc(r.detail)}` : ''}</td></tr>`; }).join('');
    const priv = rows.filter((r) => r.kind === 'model-tee').map((r) => r.id);
    const chat = priv.filter((id) => !/flux|whisper|embedding|reranker|privacy-filter/i.test(id));
    $('scan-sum').textContent = `${priv.length} of ${rows.length} models run in their own TEE.`;
    if (chat.length) {
      const was = $('model').value;
      $('model').innerHTML = chat.map((id) => `<option>${esc(id)}</option>`).join('');
      $('model').value = chat.includes(was) ? was : (chat.includes(DEFAULT_MODEL) ? DEFAULT_MODEL : chat[0]);
      $('model-hint').textContent = `${chat.length} chat models run in their own TEE right now.`;
    }
  } catch (e) { $('scan-sum').textContent = `Could not reach NEAR AI: ${e.message}`; scanned = false; }
  $('scan').disabled = false;
}
$('scan').addEventListener('click', scan);

/* Send gate */
const REDUCE = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
const wait = (ms) => new Promise((r) => setTimeout(r, REDUCE ? 0 : ms));
let gateRun = 0;
async function gate(states, note, stagger = false) {
  cancelFlash();
  const run = ++gateRun;
  $('gate-note').textContent = note || '';
  for (const li of $('gate').children) {
    if (stagger) { li.className = 'now'; await wait(170); if (run !== gateRun) return; }
    li.className = states[li.dataset.g] || '';
  }
}
const gateFrom = (v) => {
  const row = (id) => [...v.att.rows, ...v.structure].find((r) => r.id === id);
  const all = (ids) => ids.every((id) => row(id)?.ok);
  const st = (ok) => (ok ? 'ok' : 'bad');
  return {
    enclave: st(all(['model-tee', 'app', 'intel-sig', 'intel', 'nvidia'])), fresh: st(all(['nonce'])), key: st(all(['key-bound'])),
    enc: st(all(['e2ee'])), sig: st(v.calls.length > 0 && v.calls.every((c) => c.ok)),
    shown: st(v.structure.filter((r) => r.id !== 'e2ee').every((r) => r.ok)),
  };
};

/* Run */
function busy(title, note) {
  cancelFlash(); flowRun++; current = null;
  // Clear the previous run's evidence so nothing stale stays on screen.
  $('results').hidden = true; $('reply-card').hidden = true; $('proof').innerHTML = ''; $('sigs-t').tBodies[0].innerHTML = ''; $('compose').textContent = '';
  $('lens-box').textContent = ''; lensText = '';
  $('stage-title').textContent = title; $('verdict').className = 'vbadge'; $('verdict').textContent = 'Running'; $('adopt').hidden = true;
  $('break-out').innerHTML = ''; $('run-error').hidden = true;
  $('stage-run').hidden = false; $('stage-models').hidden = true;
  gate({}, note);
}
const STEP_GATE = { attest: { enclave: 'now' }, vendor: { enclave: 'now', fresh: 'now', key: 'now' }, optimize: { enclave: 'ok', fresh: 'ok', key: 'ok', enc: 'ok', sig: 'now' }, tests: { enclave: 'ok', fresh: 'ok', key: 'ok', enc: 'ok', sig: 'now' } };
const STEP_NOTE = { attest: 'Nothing sent yet.', vendor: 'Nothing sent yet.', optimize: 'Checks passed. Sent, locked to the chip.', tests: 'Tests sent, each locked too.' };
const onStep = (id, msg) => {
  gate(STEP_GATE[id] || {}, `${STEP_NOTE[id] || ''} ${msg}.`);
  const enc = $('flow').querySelector('.node[data-p="enclave"]');
  enc.classList.toggle('checking', id === 'attest' || id === 'vendor');
  if (id === 'optimize') { const l = $('flow').querySelectorAll('.wirel'); l.forEach((x) => { x.classList.remove('go'); void x.offsetWidth; x.classList.add('go'); }); }
};
$('run').addEventListener('click', async () => {
  const key = $('key').value.trim();
  const err = $('run-error');
  const fail = (m) => { err.textContent = m; err.hidden = false; };
  if (!key) return fail('Add a NEAR AI key first. Or use Check a run to verify a recorded run with no key.');
  if (preset === 'ask' && $('ask-message').value.trim().length < 2) return fail('Write a message first.');
  if (preset === 'opt' && $('prompt').value.trim().length < 40) return fail('Paste a system prompt of at least a few sentences.');
  if (preset === 'opt' && !readTests().length) return fail('Add at least one test case.');
  $('run').disabled = true;
  busy('Live run', 'Nothing sent yet. Checking the chip.');
  const op = ++opId;
  try {
    const rc = preset === 'ask'
      ? await runAsk({ key, model: $('model').value, system: $('ask-system').value, message: $('ask-message').value, onStep }, deps)
      : await runLab({ key, model: $('model').value, mode: $('mode').value, prompt: $('prompt').value.trim(), tests: readTests(), onStep }, deps);
    gate({ ...STEP_GATE.tests }, 'Checking every signature and opening every encrypted field.');
    const v = await verifyReceipt(rc, deps);
    if (op === opId) render(rc, v, 'Live run');
  } catch (e) {
    if (op !== opId) { $('run').disabled = false; return; }
    gate({}, '');
    fail(/401|403/.test(e.message) ? 'NEAR AI refused the key. Check it at cloud.near.ai.' : e.message);
    $('verdict').textContent = 'Stopped'; $('verdict').className = 'vbadge bad';
  }
  $('run').disabled = false;
});

/* Check a receipt. Every operation takes a ticket; a result that finishes after a newer one started is dropped. */
let opId = 0;
async function checkReceipt(rc, note) {
  const op = ++opId;
  busy('Checking with Intel, NVIDIA and NEAR AI', 'Re-checking a recorded run.');
  $('verdict').textContent = 'Checking';
  try {
    if (!rc || !rc.attestation || !Array.isArray(rc.calls)) throw new Error('That file is not a Private Prompt Lab receipt.');
    const v = await verifyReceipt(rc, deps);
    if (op === opId) render(rc, v, note);
  } catch (e) {
    if (op !== opId) return;
    $('run-error').textContent = e.message; $('run-error').hidden = false;
    $('verdict').textContent = 'Not checked'; $('verdict').className = 'vbadge bad';
  }
}
const samples = {};
const SAMPLE_FILES = { ask: ['sample-ask.json', 'Recorded private question'], careful: ['sample-run.json', 'Recorded private prompt edit, careful'], extreme: ['sample-extreme.json', 'Recorded private prompt edit, 40 words'] };
async function checkSample(which) {
  const btn = $(`check-${which}`); btn.disabled = true;
  const [file, note] = SAMPLE_FILES[which];
  try { samples[which] = samples[which] || await (await fetch(file)).json(); await checkReceipt(structuredClone(samples[which]), note); }
  catch (e) { $('run-error').textContent = `Could not load the sample: ${e.message}`; $('run-error').hidden = false; }
  btn.disabled = false;
}
for (const w of Object.keys(SAMPLE_FILES)) $(`check-${w}`).addEventListener('click', () => checkSample(w));
$('receipt-file').addEventListener('change', async (ev) => {
  const f = ev.target.files[0]; if (!f) return;
  try { await checkReceipt(JSON.parse(await f.text()), `Receipt file ${f.name}`); } catch { $('run-error').textContent = 'That file is not valid JSON.'; $('run-error').hidden = false; }
  ev.target.value = '';
});
// First view: a real recorded private question, checked live, before any input.
checkSample('ask');

/* Word diff (LCS on words, whitespace kept) */
function diff(a, b) {
  const A = a.split(/(\s+)/), B = b.split(/(\s+)/);
  const n = A.length, m = B.length;
  if (n * m > 4e6) return [esc(a), esc(b)];
  const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  let i = 0, j = 0, L = '', R = '';
  while (i < n && j < m) {
    if (A[i] === B[j]) { L += esc(A[i]); R += esc(B[j]); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { L += /^\s+$/.test(A[i]) ? A[i] : `<del>${esc(A[i])}</del>`; i++; }
    else { R += /^\s+$/.test(B[j]) ? B[j] : `<ins>${esc(B[j])}</ins>`; j++; }
  }
  for (; i < n; i++) L += /^\s+$/.test(A[i]) ? A[i] : `<del>${esc(A[i])}</del>`;
  for (; j < m; j++) R += /^\s+$/.test(B[j]) ? B[j] : `<ins>${esc(B[j])}</ins>`;
  return [L, R];
}

/* Who can read it: a flow of the three parties on the path (and prompt20.com, off it), and a lens
   that shows exactly what the chosen party sees, from the real request and reply bytes. */
const HEX = '0123456789abcdef';
let lens = {}; let labLens = {}; let apiLens = {}; let lensRun = 0; let lensText = ''; let flowRun = 0;
function lensData(rc, v) {
  const call = rc.calls[0];
  const plain = rc.kind === 'ask' ? [rc.system ? `[instructions]\n${rc.system}` : '', `[message]\n${rc.message}`].filter(Boolean).join('\n\n') : `[company system prompt]\n${rc.original}`;
  let body = call.request;
  try { body = JSON.stringify(JSON.parse(call.request), null, 1); } catch { /* keep raw */ }
  const reply = rc.kind === 'ask' ? v.reply : '';
  const key = String(v.att.signer || '').slice(0, 12);
  const marks = v.sensitive || [];
  return {
    browser: { title: 'What your browser sees', text: plain, marks, note: marks.length ? `Readable only here and inside the chip. Highlighted: the ${marks.length} sensitive items the chip found.` : 'Readable only here and inside the chip.' },
    gateway: { title: "What NEAR AI's gateway sees", text: body, hex: true, note: 'The exact request it received. Your words are gibberish; the model name, size, timing, IP and API key are not.' },
    enclave: { title: 'What the secure chip sees', marks, text: plain + (reply ? `\n\n[its reply, locked back to your browser]\n${reply.slice(0, 600)}${reply.length > 600 ? ' ...' : ''}` : ''), note: `Unlocked inside the chip with key ${key}..., the one in its hardware proof.` },
    prompt20: { title: 'What prompt20.com sees', text: '', note: 'Nothing from this page. Your message and key go only to NEAR AI; prompt20.com receives only the public hardware proof.' },
  };
}
const markSens = (html, items) => { let out = html; for (const it of items || []) { const e = esc(it.text); out = out.split(e).join(`<mark class="sens" title="${esc(it.type)}">${e}</mark>`); } return out; };
const escHex = (t) => esc(t).replace(/(&quot;content&quot;: &quot;)([0-9a-f]{40,})(&quot;)/g, (_, a, h, c) => `${a}<span class="hex">${h}</span>${c}`);
async function showLens(p, animate = true) {
  const d = lens[p]; if (!d) return;
  for (const n of $('flow').querySelectorAll('.node')) n.setAttribute('aria-pressed', String(n.dataset.p === p));
  $('lens-title').textContent = d.title; $('lens-note').textContent = d.note;
  const box = $('lens-box');
  box.classList.toggle('empty', !d.text);
  const target = d.text || '(nothing)';
  const run = ++lensRun;
  if (animate && !REDUCE && lensText) {
    // Scramble from the old text into the new one, left to right.
    const n = Math.min(Math.max(target.length, 1), 900); const frames = 22;
    for (let f = 1; f <= frames; f++) {
      if (run !== lensRun) return;
      const k = Math.floor((n * f) / frames);
      let tail = ''; for (let i = k; i < Math.min(n, k + 160); i++) tail += target[i] === '\n' ? '\n' : HEX[(Math.random() * 16) | 0];
      box.textContent = target.slice(0, k) + tail;
      await new Promise((r) => requestAnimationFrame(r));
    }
  }
  if (run !== lensRun) return;
  if (d.marks && !d.hex && !d.plainHit) box.innerHTML = markSens(esc(target), d.marks); else if (d.hex) box.innerHTML = escHex(target); else if (d.plainHit) box.innerHTML = esc(target).replace(/(&quot;content&quot;: &quot;)(.*?)(&quot;(?:\n|$))/g, (_, a, t, c) => `${a}<span class="leak">${markSens(t, d.marks)}</span>${c}`); else box.textContent = target;
  lensText = target;
}
async function playFlow() {
  if (cmp !== 'lab') setCmp('lab');
  const run = ++flowRun; const live = () => run === flowRun;
  const links = [...$('flow').querySelectorAll('.wirel')];
  const nodes = (p) => $('flow').querySelector(`.node[data-p="${p}"]`);
  for (const n of $('flow').querySelectorAll('.node')) n.classList.remove('lit');
  nodes('browser').classList.add('lit'); await showLens('browser'); await wait(900); if (!live()) return;
  links[0].classList.remove('go'); void links[0].offsetWidth; links[0].classList.add('go'); await wait(700); if (!live()) return;
  nodes('gateway').classList.add('lit'); await showLens('gateway'); await wait(1500); if (!live()) return;
  links[1].classList.remove('go'); void links[1].offsetWidth; links[1].classList.add('go'); await wait(700); if (!live()) return;
  nodes('enclave').classList.add('lit'); await showLens('enclave');
}
for (const n of document.querySelectorAll('#flow .node')) n.addEventListener('click', () => { flowRun++; showLens(n.dataset.p); });

/* Compare with a normal AI API: the same message in the standard request format, readable by the provider. */
let cmp = 'lab';
const NODE_TEXT = {
  lab: { browser: ['Your browser', 'Plaintext'], gateway: ['NEAR AI gateway', 'Ciphertext'], enclave: ['The enclave', 'Plaintext'], prompt20: ['prompt20.com', 'Not on the path'] },
  api: { browser: ['Your browser', 'Plaintext'], gateway: ['Provider API', 'Plaintext'], enclave: ["Provider's servers", 'Plaintext, may be logged'], prompt20: ['Tools you paste into', 'Often plaintext too'] },
};
function setCmp(mode) {
  cmp = mode;
  $('cmp-lab').setAttribute('aria-pressed', String(mode === 'lab')); $('cmp-api').setAttribute('aria-pressed', String(mode === 'api'));
  $('flow').classList.toggle('api', mode === 'api');
  for (const n of $('flow').querySelectorAll('.node')) { const [t, v] = NODE_TEXT[mode][n.dataset.p]; n.querySelector('b').textContent = t; n.querySelector('.nv').textContent = v; }
  lens = mode === 'api' ? apiLens : labLens;
  showLens(mode === 'api' ? 'gateway' : 'gateway');
}
$('cmp-lab').addEventListener('click', () => { flowRun++; setCmp('lab'); });
$('cmp-api').addEventListener('click', () => { flowRun++; setCmp('api'); });

/* Leak meter: characters of the message readable outside the browser and the chip, measured on the real bytes. */
function leakCount(plain, wireText) {
  // Count message characters that appear in the request bytes in runs of 6 or more (words, numbers, names).
  let leaked = 0; const W = 6;
  for (let i = 0; i + W <= plain.length;) {
    if (wireText.includes(plain.slice(i, i + W))) { let j = i + W; while (j < plain.length && wireText.includes(plain.slice(i, j + 1))) j++; leaked += j - i; i = j; } else i++;
  }
  return leaked;
}
const openCallOk = (c) => current?.v?.structure?.find((r) => r.id === 'e2ee')?.ok === true;
/* This run's cost in NEAR AI credits, from its real token usage and NEAR AI's published prices. */
let pricing = null;
async function costLine(rc) {
  const el = $('cost-line'); el.hidden = true;
  try {
    pricing = pricing || Object.fromEntries((await (await fetch(`${NEARAI}/models`)).json()).data.map((m) => [m.id, m.pricing]));
    const pr = pricing[rc.model]; if (!pr) return;
    let usd = 0;
    for (const c of rc.calls) { const u = JSON.parse(c.response).usage || {}; usd += ((u.prompt_tokens || 0) * pr.input + (u.completion_tokens || 0) * pr.output) / 1e6; }
    if (current?.rc !== rc) return;
    el.hidden = false;
    el.innerHTML = `This run cost <b>$${usd < 0.01 ? usd.toFixed(4) : usd.toFixed(2)}</b> in NEAR AI credits (${rc.calls.length} call${rc.calls.length === 1 ? '' : 's'}). You can pay with <a href="https://docs.near.ai/cloud/staking-for-inference/overview" target="_blank" rel="noopener">NEAR staking rewards</a>: your stake stays yours.`;
  } catch { /* prices unavailable */ }
}
function meter(rc) {
  const call = rc.calls[0];
  const msgs = rc.kind === 'ask' ? [rc.system, rc.message].filter(Boolean) : [rc.original];
  const plain = msgs.join('\n');
  // What a receiver can read after parsing the JSON body: every message content, as sent.
  const readable = (body) => { try { return JSON.parse(body).messages.map((m) => m.content).join('\n'); } catch { return body; } };
  // Encrypted and verified content is unreadable by construction; otherwise fall back to scanning the bytes.
  const labLeak = rc.calls.every((c) => openCallOk(c)) ? 0 : leakCount(plain, readable(call.request));
  const normal = JSON.stringify({ model: 'any-model', messages: msgs.map((c, i) => ({ role: i === 0 && msgs.length > 1 ? 'system' : 'user', content: c })) });
  const apiLeak = plain.length; // a standard request carries the message verbatim
  const n = plain.length;
  $('m-lab').style.width = `${Math.max(0.5, (labLeak / n) * 100)}%`; $('m-api').style.width = `${(apiLeak / n) * 100}%`;
  $('mv-lab').textContent = `${fmt(labLeak)} of ${fmt(n)} characters`;
  $('mv-api').textContent = `${fmt(apiLeak)} of ${fmt(n)} characters`;
  const items = current?.v?.sensitive;
  $('sens-row').hidden = !items || !items.length;
  if (items && items.length) {
    const byType = {}; for (const it of items) byType[it.type] = (byType[it.type] || 0) + 1;
    const lab = labLeak === 0 ? 0 : items.filter((it) => readable(call.request).includes(it.text)).length;
    $('sens-chips').innerHTML = `<b class="okc">${lab} of ${items.length}</b> readable here, <b class="badc">${items.length} of ${items.length}</b> in a standard API: ` + Object.entries(byType).map(([t, n]) => `<span class="chip">${esc(t)}${n > 1 ? ` x${n}` : ''}</span>`).join('');
  }
  $('m-note').textContent = 'What the receiving service can read. This lab: measured on the real request. Standard API: the same message in the usual format (illustration). Metadata is visible in both.';
  return normal;
}
$('replay-flow').addEventListener('click', playFlow);
$('go-try').addEventListener('click', () => showTab('run'));

/* Results */
let current = null;
/* What code is running: hardware quote, measured compose file, signed deploy log, public deploy file, engine image, gateway. */
const short = (h, n = 12) => { const t = String(h || ''); const at = t.indexOf('@sha256:'); return at >= 0 ? `${t.slice(0, at)}@sha256:${t.slice(at + 8, at + 8 + n)}` : t; };
const day = (t) => (t ? new Date(t).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' }) : '');
const ghLink = (url, label) => `<a href="${esc(url)}" target="_blank" rel="noopener">${esc(label)}</a>`;
function renderCode(code, rc) {
  const card = $('code-card');
  if (!code) { card.hidden = true; return; }
  const { compose: c, deploy: d, gateway: g } = code;
  const src = d.source;
  const pending = (x) => x === null || x === undefined;
  const intelTxt = (x, sig) => `Intel's signature ${sig ? 'checks out here' : 'FAILS here'}${pending(x) ? '' : x ? ', and the DCAP verifier agrees' : ', but the DCAP verifier did not accept it'}`;
  const links = [
    { ok: c.ok, title: 'The enclave booted this compose file', body: c.ok ? `${esc(c.name)}: its sha256 is in the hardware quote twice (MRCONFIGID and the RTMR3 event log). It pins ${c.images.map((i) => `<code>${esc(short(i))}</code>`).join(', ')}.` : 'The compose file does not match the quote.' },
    { ok: d.ok && d.intel !== false, title: 'NEAR AI\'s deploy log, signed by the same chip', body: d.present ? `${d.entries} deploy actions. Their hash and this run's nonce are in a second TDX quote from the same VM (same MRTD and RTMRs). ${intelTxt(d.intel, d.sig)}.` : 'No deploy log in this proof.' },
  ];
  if (d.containers?.length || src) {
    const ct = d.containers?.[0] || {};
    const svc = src?.service || ct.service;
    links.push({ ok: !!src?.ok, title: 'The model container, from a public file', body: src ? `${svc ? `<code>${esc(svc)}</code>, ` : ''}deployed ${esc(day(ct.at))} from ${ghLink(src.url || `https://github.com/nearai/cvm-compose-files/blob/${ct.commit}/${ct.file}`, `${ct.file} at ${String(ct.commit).slice(0, 7)}`)}. ${src.ok ? 'The file on GitHub hashes to the sha256 in the signed log.' : esc(src.error || 'The GitHub file does not match the signed log.')}` : 'Not fetched (offline).' });
    if (src?.image) {
      const pinned = /@sha256:[0-9a-f]{64}/.test(src.image) || src.built;
      links.push({ ok: pinned, mid: !pinned, title: 'The inference engine and weights', body: `Engine <code>${esc(short(src.image))}</code>${/@sha256:/.test(src.image) ? ', pinned by digest' : src.built ? ', built in the enclave from that file' : ', not pinned by digest'}.${src.weights ? ` Weights ${src.revision ? ghLink(`https://huggingface.co/${src.weights}/tree/${src.revision}`, `${src.weights} at ${src.revision.slice(0, 7)}`) : esc(src.weights)}, as labelled in that file.` : ''}` });
    }
  }
  links.push({ ok: g.ok && g.intel !== false, title: 'NEAR AI\'s gateway runs in its own enclave', body: g.present ? `The gateway that relays your ciphertext: ${g.compose.images.filter((i) => /cloud-api/.test(i)).map((i) => `<code>${esc(short(i))}</code>`).join('') || esc(g.compose.name)}. Its quote names its key and this run's nonce, and its compose file matches. ${intelTxt(g.intel, g.sig)}.` : 'No gateway proof in this run.' });
  const okN = links.filter((l) => l.ok).length;
  $('code-sum').className = `pill ${okN === links.length ? 'ok' : 'bad'}`;
  $('code-sum').textContent = `${okN} of ${links.length} linked`;
  $('code-chain').innerHTML = links.map((l) => `<li class="${l.ok ? 'ok' : l.mid ? 'mid' : 'bad'}"><b>${esc(l.title)}</b><div>${l.body}</div></li>`).join('');
  card.hidden = false;
}
const pill = (ok, yes = 'Pass', no = 'Fail') => `<span class="pill ${ok ? 'ok' : 'bad'}">${ok ? yes : no}</span>`;
function render(rc, v, note) {
  current = { rc, v, note };
  const vd = $('verdict');
  vd.className = `vbadge ${v.ok ? 'ok' : 'bad'}`;
  vd.textContent = v.ok ? 'VERIFIED' : 'NOT VERIFIED';
  const why = v.ok ? '' : v.unreachable ? ' · a verifier could not be reached, press Check again' : '';
  $('stage-title').textContent = `${note || 'This run'} · ${rc.model} · ${new Date(rc.created).toUTCString().slice(5, 22)} UTC${why}`;
  gate(gateFrom(v), v.ok ? 'All six checks passed.' : 'A check failed. Details below.', true);
  labLens = lensData(rc, v);
  const normal = meter(rc);
  costLine(rc);
  const plainAll = labLens.browser.text;
  let normalPretty = normal; try { normalPretty = JSON.stringify(JSON.parse(normal), null, 1); } catch { /* raw */ }
  apiLens = {
    browser: { title: 'What your browser sees', text: plainAll, note: 'Same as here.' },
    gateway: { title: 'What a standard AI API receives', text: normalPretty, plainHit: true, marks: v.sensitive || [], note: 'TLS protects it on the way, then the provider reads every word.' },
    enclave: { title: "What the provider's servers see", text: plainAll, note: 'Plaintext, kept under the provider\'s retention policy. You cannot check what happens to it.' },
    prompt20: { title: 'What other tools see', text: plainAll, note: 'Web tools that call an AI for you usually see your text too.' },
  };
  if (cmp === 'api') { lens = apiLens; showLens('gateway'); } else { lens = labLens; playFlow(); }
  $('break-out').innerHTML = '';

  const ad = $('adopt');
  ad.hidden = rc.kind === 'ask';
  if (rc.kind !== 'ask') { ad.className = `vbadge ${v.safe ? 'ok' : 'bad'}`; ad.textContent = v.safe ? 'Passes your tests' : v.regressions.length ? `${v.regressions.length} regression${v.regressions.length === 1 ? '' : 's'} caught` : v.ok ? 'Fails a test' : 'Not verified'; }

  const rows = [...v.att.rows, ...v.structure];
  $('proof').innerHTML = rows.map((r) => `<li>${pill(r.ok)}<div>${esc(r.label)}<div class="why">${esc(r.detail)}</div></div></li>`).join('');
  $('sigs-t').tBodies[0].innerHTML = v.calls.map((c) => `<tr><td>${esc(c.role.replace(/^test-(\d+)-/, (_, n) => `Test ${Number(n) + 1}, `))}</td><td>${pill(c.hashesOk, 'Yes', 'No')}</td><td class="mono-addr">${esc(c.recovered || 'none')}${c.kind ? ` <span class="hint">${esc(c.kind)}</span>` : ''}</td><td>${pill(c.ok)}</td></tr>`).join('');
  renderCode(v.code, rc);
  $('compose').textContent = v.att.composeHash ? `Enclave app ${v.att.appId}, compose hash ${v.att.composeHash}, key ${v.att.signer}.` : '';

  $('reply-card').hidden = rc.kind !== 'ask';
  if (rc.kind === 'ask') $('reply-text').textContent = v.reply || '';
  $('results').hidden = rc.kind === 'ask';
  if (rc.kind === 'ask') return;

  const t = v.tokens;
  const pct = t.original ? Math.round((t.savedPerCall / t.original) * 100) : 0;
  $('t-tokens').textContent = `${fmt(t.original)} → ${fmt(t.optimized)}`;
  $('t-tokens-s').textContent = `${fmt(t.savedPerCall)} fewer per call (${pct}%), Qwen tokenizer`;
  const p = prices[Number($('deploy').value)];
  const calls = Math.max(0, Number($('calls').value) || 0);
  if (p) { $('t-cost').textContent = money((t.savedPerCall * calls * p.inPrice) / 1e6); $('t-cost-s').textContent = `${fmt(calls)} calls on ${p.name}`; }
  else { $('t-cost').textContent = 'n/a'; $('t-cost-s').textContent = 'Prices did not load'; }
  const po = v.tests.filter((x) => x.original?.pass).length, pn = v.tests.filter((x) => x.optimized?.pass).length;
  $('t-tests').textContent = `${pn} of ${v.tests.length}`;
  $('t-tests-s').textContent = `Original prompt: ${po} of ${v.tests.length}${v.regressions.length ? `, ${v.regressions.length} regression${v.regressions.length === 1 ? '' : 's'}` : ''}`;
  $('tests-tile').classList.toggle('bad', !v.safe);
  const [L, R] = diff(rc.original, rc.optimized);
  $('d-old').innerHTML = L; $('d-new').innerHTML = R;
  $('changes').innerHTML = v.signed.changes.map((c) => `<li>${esc(c.change)}${c.why ? ` <span>${esc(c.why)}</span>` : ''}</li>`).join('') || '<li>None listed</li>';
  $('kept').innerHTML = v.signed.kept.map((k) => `<li>${esc(k)}</li>`).join('') || '<li>None listed</li>';
  const cell = (r) => (r ? `${pill(r.pass)}${r.fails.length ? ` <span class="hint">${esc(r.fails.join('; '))}</span>` : ''}<details><summary>Reply</summary><div class="reply">${esc(r.reply)}</div></details>` : 'n/a');
  $('tests-t').tBodies[0].innerHTML = v.tests.map((x) => { const reg = x.original?.pass && !x.optimized?.pass; return `<tr${reg ? ' class="regress"' : ''}><td>${reg ? '<span class="pill bad">Regression</span> ' : ''}${esc(x.input)}</td><td>${cell(x.original)}</td><td>${cell(x.optimized)}</td></tr>`; }).join('');
}

let flashTimer = 0;
function cancelFlash() {
  clearTimeout(flashTimer);
  for (const li of $('gate').children) if (li.dataset.was !== undefined) { li.className = li.dataset.was; delete li.dataset.was; }
  const note = $('gate-note'); if (note.dataset.base !== undefined) { note.textContent = note.dataset.base; delete note.dataset.base; }
}
function flashGate(keys, label) {
  cancelFlash();
  const note = $('gate-note'); const restore = note.dataset.base || note.textContent;
  note.dataset.base = restore;
  note.textContent = `${label}: refused.`;
  for (const li of $('gate').children) if (keys.has(li.dataset.g)) { const was = li.dataset.was || li.className; li.dataset.was = was; li.className = 'bad shake'; }
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => {
    for (const li of $('gate').children) if (li.dataset.was !== undefined) { li.className = li.dataset.was; delete li.dataset.was; }
    note.textContent = note.dataset.base; delete note.dataset.base;
  }, REDUCE ? 1500 : 2600);
}

/* Try to break it: each attack runs the real checks on a changed copy, offline, and lists what refused it. */
async function attack(label, mutate) {
  if (!current) return;
  const rc = structuredClone(current.rc);
  const why = mutate(rc);
  const v = await verifyReceipt(rc, deps, { offline: true });
  const failed = [...v.att.rows.filter((r) => !['intel', 'nvidia', 'same-app'].includes(r.id)), ...v.structure].filter((r) => !r.ok).map((r) => r.label);
  const badSigs = v.calls.filter((c) => !c.ok).length;
  if (badSigs) failed.push(`${badSigs} reply signature${badSigs === 1 ? '' : 's'}`);
  const ROW_GATE = { 'model-tee': 'enclave', app: 'enclave', 'intel-sig': 'enclave', nonce: 'fresh', 'key-bound': 'key', e2ee: 'enc' };
  const hit = new Set([...v.att.rows, ...v.structure].filter((r) => !r.ok && !['intel', 'nvidia', 'same-app'].includes(r.id)).map((r) => ROW_GATE[r.id] || 'shown'));
  if (badSigs) hit.add('sig');
  flashGate(hit, label);
  const li = document.createElement('li');
  const plain = [...$('gate').children].filter((g) => hit.has(g.dataset.g)).map((g) => g.textContent.trim());
  li.title = `Technical: ${failed.join('; ')}`;
  li.innerHTML = failed.length ? `${pill(false, '', 'Refused')} <b>${esc(label)}</b>: ${esc(why)} Breaks: ${esc(plain.join(', '))}.` : `${pill(true, 'Accepted', '')} <b>${esc(label)}</b>: nothing caught this. Please report it.`;
  $('break-out').prepend(li);
}
$('tamper').addEventListener('click', () => attack('Tamper with the reply', (rc) => {
  const c = rc.calls[0]; const i = c.response.indexOf('"content"') + 14;
  c.response = c.response.slice(0, i) + (c.response[i] === 'a' ? 'b' : 'a') + c.response.slice(i + 1);
  return 'one character changed.';
}));
$('wrongkey').addEventListener('click', () => attack('Use a fake lock', (rc) => {
  const m = modelAttestation(rc.attestation, rc.model);
  const fake = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
  m.signing_public_key = fake; m.signing_address = fake;
  return 'a lock the chip never signed.';
}));
$('forge').addEventListener('click', () => attack('Forge the hardware proof', (rc) => {
  // Write a fake key into the quote's report data, so the key-binding check alone would pass.
  const m = modelAttestation(rc.attestation, rc.model);
  const fake = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
  m.intel_quote = m.intel_quote.slice(0, 568 * 2) + fake + m.intel_quote.slice(600 * 2);
  m.signing_public_key = fake; m.signing_address = fake;
  return 'the quote rewritten to name a key the attacker holds.';
}));
$('replay').addEventListener('click', () => attack('Replay an old proof', (rc) => {
  rc.nonce = newNonce();
  return 'an old proof for a new check.';
}));
$('outside').addEventListener('click', async () => {
  const li = document.createElement('li');
  try {
    await runAsk({ key: 'not-needed', model: 'anthropic/claude-sonnet-5-5', message: 'test' }, deps);
    li.innerHTML = `${pill(true, 'Sent', '')} <b>Non-TEE model</b>: a message was sent. Please report it.`;
  } catch (e) {
    if (/outside provider/.test(e.message)) {
      flashGate(new Set(['enclave']), 'Send to Claude (not private)');
      li.innerHTML = `${pill(false, '', 'Refused')} <b>Send to Claude (not private)</b>: ${esc(e.message)}`;
    } else li.innerHTML = `<span class="pill mid">Unknown</span> <b>Send to Claude (not private)</b>: could not reach NEAR AI to check (${esc(e.message)}).`;
  }
  $('break-out').prepend(li);
});

$('fresh').addEventListener('click', async () => {
  if (!current) return;
  const { rc, note } = current;
  $('fresh').disabled = true;
  try { await checkReceipt(rc, `${note || 'This run'}, checked again`); } finally { $('fresh').disabled = false; }
});
$('download').addEventListener('click', () => {
  if (!current) return;
  if (!confirm('This receipt contains the secrets that open its messages. Anyone you give it to can read the prompt and the replies. Download it?')) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(current.rc)], { type: 'application/json' }));
  a.download = `private-prompt-receipt-${current.rc.created.slice(0, 19).replace(/[:T]/g, '-')}.json`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
$('copy-opt').addEventListener('click', async () => { if (current?.rc.optimized) { try { await navigator.clipboard.writeText(current.rc.optimized); $('copy-opt').textContent = 'Copied'; setTimeout(() => { $('copy-opt').textContent = 'Copy the optimised prompt'; }, 1500); } catch { /* clipboard blocked */ } } });
