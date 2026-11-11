/* Private Prompt Lab page. All checks live in engine.js, shared with the Node verifier. */
import { runLab, verifyReceipt, fetchAttestation, privacyKind, newNonce, NEARAI, DEFAULT_MODEL } from './engine.js';
import { SAMPLE_PROMPT, SAMPLE_TESTS } from './sample.js';

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

const store = {
  get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
  set: (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* storage blocked */ } },
};

/* Tabs */
const tabs = ['run', 'check', 'models'];
function showTab(t) {
  for (const x of tabs) { $(`tab-${x}`).setAttribute('aria-selected', String(x === t)); $(`p-${x}`).hidden = x !== t; }
  if (t === 'models' && !scanned) scan();
}
for (const t of tabs) $(`tab-${t}`).addEventListener('click', () => showTab(t));

/* Key */
const savedKey = store.get('p20.nearai.key');
if (savedKey) { $('key').value = savedKey; $('remember').checked = true; }
$('remember').addEventListener('change', () => store.set('p20.nearai.key', $('remember').checked ? $('key').value.trim() : null));
$('key').addEventListener('input', () => { if ($('remember').checked) store.set('p20.nearai.key', $('key').value.trim()); });

/* Prompt + tests */
function promptCount() { const w = $('prompt').value.trim().split(/\s+/).filter(Boolean).length; $('prompt-count').textContent = w ? `${fmt(w)} words` : ''; }
$('prompt').addEventListener('input', promptCount);
function testRow(t = { input: '', must: [], mustNot: [] }) {
  const d = document.createElement('div');
  d.className = 'test';
  d.innerHTML = `<textarea rows="2" aria-label="Test message" placeholder="A message a user might send">${esc(t.input)}</textarea>
    <label>Reply must include<input type="text" class="must" value="${esc((t.must || []).join(', '))}" placeholder="30 days | 30-day, - Nova"></label>
    <label>Reply must not include<input type="text" class="mustnot" value="${esc((t.mustNot || []).join(', '))}"></label>
    <button type="button" class="btn ghost rm" aria-label="Remove this test case">Remove</button>`;
  d.querySelector('.rm').addEventListener('click', () => d.remove());
  $('tests').append(d);
}
const split = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
const readTests = () => [...$('tests').children].map((d) => ({ input: d.querySelector('textarea').value.trim(), must: split(d.querySelector('.must').value), mustNot: split(d.querySelector('.mustnot').value) })).filter((t) => t.input);
function loadSample() { $('prompt').value = SAMPLE_PROMPT; $('tests').innerHTML = ''; SAMPLE_TESTS.forEach(testRow); promptCount(); }
$('load-sample').addEventListener('click', loadSample);
$('add-test').addEventListener('click', () => testRow());
loadSample();

/* Deploy-model prices from data.prompt20.com */
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
  // Default to the newest Claude Sonnet, a common production choice.
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
  'model-tee': ['ok', 'Private', 'Runs in its own TEE, with its own signing key'],
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
    // The optimiser needs a chat model: leave out image, speech, embedding and filter models.
    const chatPriv = priv.filter((id) => !/flux|whisper|embedding|reranker|privacy-filter/i.test(id));
    $('scan-sum').textContent = `${priv.length} of ${rows.length} models run in their own TEE.`;
    if (chatPriv.length) {
      const was = $('model').value;
      $('model').innerHTML = chatPriv.map((id) => `<option>${esc(id)}</option>`).join('');
      $('model').value = chatPriv.includes(was) ? was : (chatPriv.includes(DEFAULT_MODEL) ? DEFAULT_MODEL : chatPriv[0]);
      $('model-hint').textContent = `${chatPriv.length} chat models run in their own TEE right now.`;
    }
  } catch (e) { $('scan-sum').textContent = `Could not reach NEAR AI: ${e.message}`; scanned = false; }
  $('scan').disabled = false;
}
$('scan').addEventListener('click', scan);
$('model').addEventListener('focus', () => { if (!scanned) scan(); }, { once: true });

/* Run */
const STEPS = { attest: 0, vendor: 1, optimize: 2, tests: 3 };
function stepUI(id, msg) {
  const ol = $('steps'); ol.hidden = false;
  const idx = STEPS[id];
  [...ol.children].forEach((li, i) => { li.className = i < idx ? 'done' : ''; });
  if (!ol.children[idx]) { const li = document.createElement('li'); ol.append(li); }
  ol.children[idx].textContent = msg; ol.children[idx].className = 'now';
}
$('run').addEventListener('click', async () => {
  const key = $('key').value.trim(); const prompt = $('prompt').value.trim(); const tests = readTests();
  const err = $('run-error'); err.hidden = true;
  if (!key) { err.textContent = 'Add a NEAR AI key first. Or open "Check a run" to verify the recorded sample with no key.'; err.hidden = false; return; }
  if (prompt.length < 40) { err.textContent = 'Paste a system prompt of at least a few sentences.'; err.hidden = false; return; }
  if (!tests.length) { err.textContent = 'Add at least one test case.'; err.hidden = false; return; }
  $('run').disabled = true; $('steps').innerHTML = '';
  try {
    const rc = await runLab({ key, model: $('model').value, prompt, tests, onStep: stepUI }, deps);
    stepUI('tests', 'Checking every signature');
    const v = await verifyReceipt(rc, deps);
    [...$('steps').children].forEach((li) => { li.className = 'done'; });
    render(rc, v);
  } catch (e) {
    err.textContent = /401|403/.test(e.message) ? 'NEAR AI refused the key. Check it at cloud.near.ai.' : e.message; err.hidden = false;
  }
  $('run').disabled = false;
});

/* Check a receipt */
async function checkReceipt(rc, note) {
  const err = $('check-error'); err.hidden = true;
  try {
    if (!rc || !rc.attestation || !Array.isArray(rc.calls)) throw new Error('That file is not a Private Prompt Lab receipt.');
    render(rc, await verifyReceipt(rc, deps), note);
  } catch (e) { err.textContent = e.message; err.hidden = false; }
}
let sample = null;
$('check-sample').addEventListener('click', async () => {
  $('check-sample').disabled = true;
  try { sample = sample || await (await fetch('sample-run.json')).json(); await checkReceipt(structuredClone(sample), 'Recorded sample run, checked again in your browser'); }
  catch (e) { $('check-error').textContent = `Could not load the sample: ${e.message}`; $('check-error').hidden = false; }
  $('check-sample').disabled = false;
});
$('receipt-file').addEventListener('change', async (ev) => {
  const f = ev.target.files[0]; if (!f) return;
  try { await checkReceipt(JSON.parse(await f.text()), `Receipt file ${f.name}`); } catch { $('check-error').textContent = 'That file is not valid JSON.'; $('check-error').hidden = false; }
  ev.target.value = '';
});
fetch('sample-run.json', { method: 'HEAD' }).then((r) => { const d = r.headers.get('last-modified'); if (d) $('sample-date').textContent = `NEAR AI Cloud on ${new Date(d).toUTCString().slice(5, 16)}`; }).catch(() => {});

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

/* Results */
let current = null;
const pill = (ok, yes = 'Pass', no = 'Fail') => `<span class="pill ${ok ? 'ok' : 'bad'}">${ok ? yes : no}</span>`;
function render(rc, v, note) {
  current = { rc, v, note };
  $('results').hidden = false;
  const vd = $('verdict');
  vd.className = `verdict ${v.ok ? 'ok' : 'bad'}`;
  const why = v.ok ? '' : v.unreachable ? ' · a verifier could not be reached, press Check again' : '';
  vd.innerHTML = `${v.ok ? 'VERIFIED' : 'NOT VERIFIED'}<small>${esc(note || 'This run')} · ${esc(rc.model)} · ${esc(new Date(rc.created).toUTCString())}${why}</small>`;

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
  $('t-tests-s').textContent = `Original prompt: ${po} of ${v.tests.length}`;
  const sOk = v.calls.filter((c) => c.ok).length;
  $('t-sigs').textContent = `${sOk} of ${v.calls.length}`;
  $('t-sigs-s').textContent = 'Signed in the enclave, checked here';

  const [L, R] = diff(rc.original, rc.optimized);
  $('d-old').innerHTML = L; $('d-new').innerHTML = R;
  $('changes').innerHTML = v.signed.changes.map((c) => `<li>${esc(c.change)}${c.why ? ` <span>${esc(c.why)}</span>` : ''}</li>`).join('') || '<li>None listed</li>';
  $('kept').innerHTML = v.signed.kept.map((k) => `<li>${esc(k)}</li>`).join('') || '<li>None listed</li>';

  const cell = (r) => (r ? `${pill(r.pass)}${r.fails.length ? ` <span class="hint">${esc(r.fails.join('; '))}</span>` : ''}<details><summary>Reply</summary><div class="reply">${esc(r.reply)}</div></details>` : 'n/a');
  $('tests-t').tBodies[0].innerHTML = v.tests.map((x) => `<tr><td>${esc(x.input)}</td><td>${cell(x.original)}</td><td>${cell(x.optimized)}</td></tr>`).join('');

  const rows = [...v.att.rows, ...v.structure];
  $('proof').innerHTML = rows.map((r) => `<li>${pill(r.ok)}<div>${esc(r.label)}<div class="why">${esc(r.detail)}</div></div></li>`).join('');
  $('sigs-t').tBodies[0].innerHTML = v.calls.map((c) => `<tr><td>${esc(c.role.replace(/^test-(\d+)-/, (_, n) => `Test ${Number(n) + 1}, `))}</td><td>${pill(c.hashesOk, 'Yes', 'No')}</td><td class="mono-addr">${esc(c.recovered || 'none')}${c.kind ? ` <span class="hint">${esc(c.kind)}</span>` : ''}</td><td>${pill(c.ok)}</td></tr>`).join('');
  $('compose').textContent = v.att.composeHash ? `Enclave app ${v.att.appId}, compose hash ${v.att.composeHash}, signing key ${v.att.signer}. Pass and fail are recomputed from the signed replies; the must and must-not rules are yours.` : '';
  $('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

$('tamper').addEventListener('click', async () => {
  if (!current) return;
  const rc = structuredClone(current.rc);
  const c = rc.calls.find((x) => x.role === 'optimize');
  const i = c.response.indexOf('"content"') + 12;
  c.response = c.response.slice(0, i) + (c.response[i] === 'a' ? 'b' : 'a') + c.response.slice(i + 1);
  render(rc, await verifyReceipt(rc, deps), 'Tampered copy: one byte flipped in the optimiser reply');
});
$('fresh').addEventListener('click', async () => {
  if (!current) return;
  $('fresh').disabled = true;
  render(current.rc, await verifyReceipt(current.rc, deps), `${current.note || 'This run'}, checked again`);
  $('fresh').disabled = false;
});
$('download').addEventListener('click', () => {
  if (!current) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(current.rc)], { type: 'application/json' }));
  a.download = `private-prompt-receipt-${current.rc.created.slice(0, 19).replace(/[:T]/g, '-')}.json`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});
$('copy-opt').addEventListener('click', async () => { if (current) { try { await navigator.clipboard.writeText(current.rc.optimized); $('copy-opt').textContent = 'Copied'; setTimeout(() => { $('copy-opt').textContent = 'Copy the optimised prompt'; }, 1500); } catch { /* clipboard blocked */ } } });
