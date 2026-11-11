/* Private Prompt Lab page. All checks live in engine.js, shared with the Node verifier.
   Imports carry the release tag so a deploy never mixes a cached old module with new ones. */
import { runLab, runAsk, verifyReceipt, fetchAttestation, privacyKind, newNonce, modelAttestation, NEARAI, DEFAULT_MODEL } from './engine.js?v=7';
import { SAMPLE_PROMPT, SAMPLE_TESTS, SAMPLE_ASK } from './sample.js?v=7';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = (n) => (n == null || Number.isNaN(n) ? 'n/a' : Number(n).toLocaleString('en-US'));
const money = (n) => (n >= 100 ? `$${Math.round(n).toLocaleString('en-US')}` : `$${n.toFixed(2)}`);

const deps = {
  fetch: (...a) => window.fetch(...a),
  recover: (msg, sig) => window.ethers.verifyMessage(msg, sig),
  // Intel's and NVIDIA's verifiers send no CORS headers, so prompt20.com passes the public evidence through.
  tdxUrl: new URL('verify/tdx', location.href).href,
  gpuUrl: new URL('verify/gpu', location.href).href,
};

/* Tabs */
const tabs = ['run', 'check', 'models'];
function showTab(t) {
  for (const x of tabs) { $(`tab-${x}`).setAttribute('aria-selected', String(x === t)); $(`p-${x}`).hidden = x !== t; }
  $('stage-run').hidden = t === 'models'; $('stage-models').hidden = t !== 'models';
  if (t === 'models' && !scanned) scan();
}
for (const t of tabs) $(`tab-${t}`).addEventListener('click', () => showTab(t));

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
function gate(states, note) {
  for (const li of $('gate').children) { li.className = states[li.dataset.g] || ''; }
  $('gate-note').textContent = note || '';
}
const gateFrom = (v) => {
  const row = (id) => [...v.att.rows, ...v.structure].find((r) => r.id === id);
  const all = (ids) => ids.every((id) => row(id)?.ok);
  const st = (ok) => (ok ? 'ok' : 'bad');
  return {
    enclave: st(all(['model-tee', 'app', 'intel', 'nvidia'])), fresh: st(all(['nonce'])), key: st(all(['key-bound'])),
    enc: st(all(['e2ee'])), sig: st(v.calls.length > 0 && v.calls.every((c) => c.ok)),
    shown: st(v.structure.filter((r) => r.id !== 'e2ee').every((r) => r.ok)),
  };
};

/* Run */
function busy(title, note) {
  $('stage-title').textContent = title; $('verdict').className = 'vbadge'; $('verdict').textContent = 'Running'; $('adopt').hidden = true;
  $('break-out').innerHTML = ''; $('run-error').hidden = true;
  $('stage-run').hidden = false; $('stage-models').hidden = true;
  gate({}, note);
}
const STEP_GATE = { attest: { enclave: 'now' }, vendor: { enclave: 'now', fresh: 'now', key: 'now' }, optimize: { enclave: 'ok', fresh: 'ok', key: 'ok', enc: 'ok', sig: 'now' }, tests: { enclave: 'ok', fresh: 'ok', key: 'ok', enc: 'ok', sig: 'now' } };
const STEP_NOTE = { attest: 'No prompt sent yet.', vendor: 'No prompt sent yet.', optimize: 'Checks passed. Sent, encrypted to the enclave key.', tests: 'Each test message is encrypted too.' };
const onStep = (id, msg) => gate(STEP_GATE[id] || {}, `${STEP_NOTE[id] || ''} ${msg}.`);
$('run').addEventListener('click', async () => {
  const key = $('key').value.trim();
  const err = $('run-error');
  const fail = (m) => { err.textContent = m; err.hidden = false; };
  if (!key) return fail('Add a NEAR AI key first. Or use Check a run to verify a recorded run with no key.');
  if (preset === 'ask' && $('ask-message').value.trim().length < 2) return fail('Write a message first.');
  if (preset === 'opt' && $('prompt').value.trim().length < 40) return fail('Paste a system prompt of at least a few sentences.');
  if (preset === 'opt' && !readTests().length) return fail('Add at least one test case.');
  $('run').disabled = true;
  busy('Live run', 'No prompt sent yet. Checking the enclave.');
  try {
    const rc = preset === 'ask'
      ? await runAsk({ key, model: $('model').value, system: $('ask-system').value, message: $('ask-message').value, onStep }, deps)
      : await runLab({ key, model: $('model').value, mode: $('mode').value, prompt: $('prompt').value.trim(), tests: readTests(), onStep }, deps);
    gate({ ...STEP_GATE.tests }, 'Checking every signature and opening every encrypted field.');
    render(rc, await verifyReceipt(rc, deps), 'Live run');
  } catch (e) {
    gate({}, '');
    fail(/401|403/.test(e.message) ? 'NEAR AI refused the key. Check it at cloud.near.ai.' : e.message);
    $('verdict').textContent = 'Stopped'; $('verdict').className = 'vbadge bad';
  }
  $('run').disabled = false;
});

/* Check a receipt */
async function checkReceipt(rc, note) {
  busy('Checking with Intel, NVIDIA and NEAR AI', 'Re-checking a recorded run: hardware, keys, encryption and signatures.');
  $('verdict').textContent = 'Checking';
  try {
    if (!rc || !rc.attestation || !Array.isArray(rc.calls)) throw new Error('That file is not a Private Prompt Lab receipt.');
    render(rc, await verifyReceipt(rc, deps), note);
  } catch (e) { $('run-error').textContent = e.message; $('run-error').hidden = false; }
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

/* The wire view: what the person wrote, beside the exact request body NEAR AI's gateway received. */
function wire(rc) {
  const call = rc.calls[0];
  const plain = rc.kind === 'ask' ? [rc.system ? `[instructions]\n${rc.system}` : '', `[message]\n${rc.message}`].filter(Boolean).join('\n\n') : `[system prompt sent for editing]\n${rc.original}`;
  $('wire-plain').textContent = plain;
  let body = call.request;
  try { body = JSON.stringify(JSON.parse(call.request), null, 1); } catch { /* keep raw */ }
  $('wire-cipher').innerHTML = esc(body).replace(/(&quot;content&quot;: &quot;)([0-9a-f]{40,})(&quot;)/g, (_, a, hex, c) => `${a}<span class="hex">${hex}</span>${c}`);
}

/* Results */
let current = null;
const pill = (ok, yes = 'Pass', no = 'Fail') => `<span class="pill ${ok ? 'ok' : 'bad'}">${ok ? yes : no}</span>`;
function render(rc, v, note) {
  current = { rc, v, note };
  const vd = $('verdict');
  vd.className = `vbadge ${v.ok ? 'ok' : 'bad'}`;
  vd.textContent = v.ok ? 'VERIFIED' : 'NOT VERIFIED';
  const why = v.ok ? '' : v.unreachable ? ' · a verifier could not be reached, press Check again' : '';
  $('stage-title').textContent = `${note || 'This run'} · ${rc.model} · ${new Date(rc.created).toUTCString().slice(5, 22)} UTC${why}`;
  gate(gateFrom(v), v.ok ? 'Every step verified. The prompt left the browser only as ciphertext, to the key in the hardware quote.' : 'A step failed. See Every check below.');
  $('who-enclave').textContent = `Only the holder of key ${String(v.att.signer || '').slice(0, 12)}..., named in the hardware quote with this run's nonce, can decrypt.`;
  wire(rc);
  $('break-out').innerHTML = '';

  const ad = $('adopt');
  ad.hidden = rc.kind === 'ask';
  if (rc.kind !== 'ask') { ad.className = `vbadge ${v.safe ? 'ok' : 'bad'}`; ad.textContent = v.safe ? 'Safe to adopt' : v.regressions.length ? `${v.regressions.length} regression${v.regressions.length === 1 ? '' : 's'} caught` : v.ok ? 'Fails a test' : 'Not verified'; }

  const rows = [...v.att.rows, ...v.structure];
  $('proof').innerHTML = rows.map((r) => `<li>${pill(r.ok)}<div>${esc(r.label)}<div class="why">${esc(r.detail)}</div></div></li>`).join('');
  $('sigs-t').tBodies[0].innerHTML = v.calls.map((c) => `<tr><td>${esc(c.role.replace(/^test-(\d+)-/, (_, n) => `Test ${Number(n) + 1}, `))}</td><td>${pill(c.hashesOk, 'Yes', 'No')}</td><td class="mono-addr">${esc(c.recovered || 'none')}${c.kind ? ` <span class="hint">${esc(c.kind)}</span>` : ''}</td><td>${pill(c.ok)}</td></tr>`).join('');
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
  const sOk = v.calls.filter((c) => c.ok).length;
  $('t-sigs').textContent = `${sOk} of ${v.calls.length}`;
  $('t-sigs-s').textContent = 'Encrypted, signed in the enclave, checked here';
  const [L, R] = diff(rc.original, rc.optimized);
  $('d-old').innerHTML = L; $('d-new').innerHTML = R;
  $('changes').innerHTML = v.signed.changes.map((c) => `<li>${esc(c.change)}${c.why ? ` <span>${esc(c.why)}</span>` : ''}</li>`).join('') || '<li>None listed</li>';
  $('kept').innerHTML = v.signed.kept.map((k) => `<li>${esc(k)}</li>`).join('') || '<li>None listed</li>';
  const cell = (r) => (r ? `${pill(r.pass)}${r.fails.length ? ` <span class="hint">${esc(r.fails.join('; '))}</span>` : ''}<details><summary>Reply</summary><div class="reply">${esc(r.reply)}</div></details>` : 'n/a');
  $('tests-t').tBodies[0].innerHTML = v.tests.map((x) => { const reg = x.original?.pass && !x.optimized?.pass; return `<tr${reg ? ' class="regress"' : ''}><td>${reg ? '<span class="pill bad">Regression</span> ' : ''}${esc(x.input)}</td><td>${cell(x.original)}</td><td>${cell(x.optimized)}</td></tr>`; }).join('');
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
  const li = document.createElement('li');
  li.innerHTML = failed.length ? `${pill(false, '', 'Refused')} <b>${esc(label)}</b>: ${esc(why)} Failed: ${esc(failed.join('; '))}.` : `${pill(true, 'Accepted', '')} <b>${esc(label)}</b>: nothing caught this. Please report it.`;
  $('break-out').prepend(li);
}
$('tamper').addEventListener('click', () => attack('Flip a byte', (rc) => {
  const c = rc.calls[0]; const i = c.response.indexOf('"content"') + 14;
  c.response = c.response.slice(0, i) + (c.response[i] === 'a' ? 'b' : 'a') + c.response.slice(i + 1);
  return 'one hex character of the encrypted reply changed.';
}));
$('wrongkey').addEventListener('click', () => attack('Swap in another key', (rc) => {
  const m = modelAttestation(rc.attestation, rc.model);
  const fake = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
  m.signing_public_key = fake; m.signing_address = fake;
  return 'the receipt now names a key the quote does not contain.';
}));
$('replay').addEventListener('click', () => attack('Replay to a new challenge', (rc) => {
  rc.nonce = newNonce();
  return 'the old quote is offered against a fresh random challenge.';
}));
$('outside').addEventListener('click', async () => {
  const li = document.createElement('li');
  try {
    await runAsk({ key: 'not-needed', model: 'anthropic/claude-sonnet-5-5', message: 'test' }, deps);
    li.innerHTML = `${pill(true, 'Sent', '')} <b>Non-TEE model</b>: a message was sent. Please report it.`;
  } catch (e) {
    li.innerHTML = `${pill(false, '', 'Refused')} <b>Send to a non-TEE model</b> (anthropic/claude-sonnet-5-5 on NEAR AI): ${esc(e.message)}`;
  }
  $('break-out').prepend(li);
});

$('fresh').addEventListener('click', async () => {
  if (!current) return;
  $('fresh').disabled = true;
  render(current.rc, await verifyReceipt(current.rc, deps), `${current.note || 'This run'}, checked again`);
  $('fresh').disabled = false;
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
