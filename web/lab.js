/* Private Prompt Lab page. All checks live in engine.js, shared with the Node verifier.
   Imports carry the release tag so a deploy never mixes a cached old module with new ones. */
import { runAsk, verifyReceipt, fetchAttestation, privacyKind, newNonce, modelAttestation, NEARAI, DEFAULT_MODEL } from './engine.js?v=17';
import { SAMPLE_ASK } from './sample.js?v=17';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = (n) => (n == null || Number.isNaN(n) ? 'n/a' : Number(n).toLocaleString('en-US'));

/* Every request has a deadline, so a stalled service shows an error instead of spinning forever.
   Reads (GET) retry twice on a network error, 429 or 5xx; sends (POST) never retry, so a message is
   never sent twice. */
const TIMEOUT_MS = { chat: 180000, other: 30000 };
async function timedFetch(url, opts = {}) {
  const u = String(url); const isGet = !opts.method || opts.method === 'GET';
  const ms = /\/chat\/completions$/.test(u) ? TIMEOUT_MS.chat : TIMEOUT_MS.other;
  for (let attempt = 0; ; attempt++) {
    try {
      const r = await window.fetch(url, { ...opts, signal: opts.signal || AbortSignal.timeout(ms) });
      if (isGet && attempt < 2 && [429, 502, 504].includes(r.status)) { await new Promise((ok) => setTimeout(ok, 600 * 2 ** attempt)); continue; }
      return r;
    } catch (e) {
      const host = new URL(u, location.href).host;
      if (e.name === 'TimeoutError') throw new Error(`${host} did not answer within ${ms / 1000} seconds.`);
      if (isGet && attempt < 2) { await new Promise((ok) => setTimeout(ok, 600 * 2 ** attempt)); continue; }
      throw new Error(`Could not reach ${host}. Check your connection and try again.`);
    }
  }
}
const deps = {
  fetch: timedFetch,
  // Intel's PCS and NVIDIA's verifier send no CORS headers, so prompt20.com passes the public evidence
  // through. Intel's collateral is signed by Intel and checked here, so the pass-through cannot alter it.
  pcsUrl: (kind, arg) => new URL(`intel/${kind}${arg ? `/${arg}` : ''}`, location.href).href,
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

/* Inputs */
function loadAsk() { $('ask-system').value = SAMPLE_ASK.system; $('ask-message').value = SAMPLE_ASK.message; }
$('load-ask').addEventListener('click', loadAsk);
loadAsk();

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
    const list = (await (await timedFetch(`${NEARAI}/models`)).json()).data.map((m) => m.id);
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
  $('reply-card').hidden = true; $('proof').innerHTML = ''; $('sigs-t').tBodies[0].innerHTML = ''; $('compose').textContent = '';
  $('lens-box').textContent = ''; lensText = '';
  $('stage-title').textContent = title; $('verdict').className = 'vbadge'; $('verdict').textContent = 'Running';
  $('break-out').innerHTML = ''; $('run-error').hidden = true;
  $('stage-run').hidden = false; $('stage-models').hidden = true;
  gate({}, note);
}
const STEP_GATE = { attest: { enclave: 'now' }, vendor: { enclave: 'now', fresh: 'now', key: 'now' }, send: { enclave: 'ok', fresh: 'ok', key: 'ok', enc: 'ok', sig: 'now' } };
const STEP_NOTE = { attest: 'Nothing sent yet.', vendor: 'Nothing sent yet.', send: 'Checks passed. Sent, locked to the chip.' };
const onStep = (id, msg) => {
  gate(STEP_GATE[id] || {}, `${STEP_NOTE[id] || ''} ${msg}.`);
  const enc = $('flow').querySelector('.node[data-p="enclave"]');
  enc.classList.toggle('checking', id === 'attest' || id === 'vendor');
  if (id === 'send') { const l = $('flow').querySelectorAll('.wirel'); l.forEach((x) => { x.classList.remove('go'); void x.offsetWidth; x.classList.add('go'); }); }
};
$('run').addEventListener('click', async () => {
  const key = $('key').value.trim();
  const err = $('run-error');
  const fail = (m) => { err.textContent = m; err.hidden = false; };
  if (!key) return fail('Add a NEAR AI key first. The Demo tab checks a recorded run with no key.');
  if ($('ask-message').value.trim().length < 2) return fail('Write a message first.');
  $('run').disabled = true;
  busy('Live run', 'Nothing sent yet. Checking the chip.');
  const op = ++opId;
  try {
    const rc = await runAsk({ key, model: $('model').value, system: $('ask-system').value, message: $('ask-message').value, onStep }, deps);
    gate({ ...STEP_GATE.send }, 'Checking every signature and opening every encrypted field.');
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
const SAMPLE_FILES = { ask: ['sample-ask.json', 'Recorded private question'] };
async function checkSample(which) {
  const btn = $(`check-${which}`); btn.disabled = true;
  const [file, note] = SAMPLE_FILES[which];
  try { samples[which] = samples[which] || await (await timedFetch(file)).json(); await checkReceipt(structuredClone(samples[which]), note); }
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

/* Who can read it: a flow of the three parties on the path (and prompt20.com, off it), and a lens
   that shows exactly what the chosen party sees, from the real request and reply bytes. */
const HEX = '0123456789abcdef';
let lens = {}; let lensRun = 0; let lensText = ''; let flowRun = 0;
function lensData(rc, v) {
  const call = rc.calls[0];
  const plain = [rc.system ? `[instructions]\n${rc.system}` : '', `[message]\n${rc.message}`].filter(Boolean).join('\n\n');
  let body = call.request;
  try { body = JSON.stringify(JSON.parse(call.request), null, 1); } catch { /* keep raw */ }
  const reply = v.reply || '';
  const key = String(v.att.signer || '').slice(0, 12);
  const marks = v.sensitive || [];
  return {
    browser: { title: 'What your browser sees', text: plain, marks, note: marks.length ? `Readable only here and inside the chip. Highlighted: the ${marks.length} sensitive items the chip found.` : 'Readable only here and inside the chip.' },
    gateway: { title: "What NEAR AI's gateway sees", text: body, hex: true, note: 'The exact request it received. Your words are gibberish; the model name, size, timing, IP and API key are not.' },
    enclave: { title: 'What the secure chip sees', marks, text: plain + (reply ? `\n\n[its reply, locked back to your browser]\n${reply.slice(0, 600)}${reply.length > 600 ? ' ...' : ''}` : ''), note: `Unlocked inside the chip with key ${key}..., the one in its hardware proof.` },
    api: { title: 'What a standard AI API receives', text: standardRequest(rc), plainHit: true, marks, note: 'The same message sent the usual way. TLS protects it on the way, then the provider reads every word and keeps it under its own retention policy.' },
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

/* Readable in transit: measured on the real request bytes, against the same message sent the usual way. */
function leakCount(plain, wireText) {
  // Count message characters that appear in the request bytes in runs of 6 or more (words, numbers, names).
  let leaked = 0; const W = 6;
  for (let i = 0; i + W <= plain.length;) {
    if (wireText.includes(plain.slice(i, i + W))) { let j = i + W; while (j < plain.length && wireText.includes(plain.slice(i, j + 1))) j++; leaked += j - i; i = j; } else i++;
  }
  return leaked;
}
const sentTexts = (rc) => [rc.system, rc.message].filter((x) => String(x || '').trim());
function standardRequest(rc) {
  const msgs = sentTexts(rc);
  return JSON.stringify({ model: 'any-model', messages: msgs.map((c, i) => ({ role: i === 0 && msgs.length > 1 ? 'system' : 'user', content: c })) }, null, 1);
}
/* This run's cost in NEAR AI credits, from its real token usage and NEAR AI's published prices. */
let pricing = null;
async function costLine(rc) {
  const el = $('cost-line'); el.hidden = true;
  try {
    pricing = pricing || Object.fromEntries((await (await timedFetch(`${NEARAI}/models`)).json()).data.map((m) => [m.id, m.pricing]));
    const pr = pricing[rc.model]; if (!pr) return;
    let usd = 0;
    for (const c of rc.calls) { const u = JSON.parse(c.response).usage || {}; usd += ((u.prompt_tokens || 0) * pr.input + (u.completion_tokens || 0) * pr.output) / 1e6; }
    if (current?.rc !== rc) return;
    el.hidden = false;
    el.innerHTML = `Cost <b>$${usd < 0.01 ? usd.toFixed(4) : usd.toFixed(2)}</b> in NEAR AI credits, payable with <a href="https://docs.near.ai/cloud/staking-for-inference/overview" target="_blank" rel="noopener">NEAR staking</a> <button type="button" class="itip" data-tip="${rc.calls.length} call${rc.calls.length === 1 ? '' : 's'}, priced from their real token usage and NEAR AI's published prices. Staking for Inference pays credits from NEAR staking rewards, and the stake stays yours." aria-label="What is this?">i</button>`;
  } catch { /* prices unavailable */ }
}
function meter(rc, v) {
  const plain = sentTexts(rc).join('\n');
  // What a receiver can read after parsing the JSON body: every message content, as sent.
  const readable = (body) => { try { return JSON.parse(body).messages.map((m) => m.content).join('\n'); } catch { return body; } };
  // Encrypted and verified content is unreadable by construction; otherwise scan the bytes.
  const e2eeOk = v.structure.find((r) => r.id === 'e2ee')?.ok === true;
  const wire = readable(rc.calls[0].request);
  const items = v.sensitive || [];
  let html;
  if (items.length) {
    const byType = {}; for (const it of items) byType[it.type] = (byType[it.type] || 0) + 1;
    const here = e2eeOk ? 0 : items.filter((it) => wire.includes(it.text)).length;
    html = `<b class="${here ? 'badc' : 'okc'}">${here} of ${items.length}</b> sensitive items here, <b class="badc">${items.length} of ${items.length}</b> with a standard AI API: ${Object.entries(byType).map(([t, n]) => `<span class="chip">${esc(t)}${n > 1 ? ` x${n}` : ''}</span>`).join('')}`;
  } else {
    const n = plain.length; const here = e2eeOk ? 0 : leakCount(plain, wire);
    html = `<b class="${here ? 'badc' : 'okc'}">${fmt(here)} of ${fmt(n)}</b> characters here, <b class="badc">${fmt(n)} of ${fmt(n)}</b> with a standard AI API`;
  }
  $('sens-chips').innerHTML = html;
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
  const intelTxt = (x, sig) => `Intel's signature ${sig ? 'checks out here' : 'FAILS here'}${pending(x) ? '' : x ? ', and Intel\'s collateral says the platform is up to date and not revoked' : ', but Intel\'s collateral check failed'}`;
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
  lens = lensData(rc, v);
  meter(rc, v);
  costLine(rc);
  playFlow();
  $('break-out').innerHTML = '';

  const rows = [...v.att.rows, ...v.structure];
  $('proof').innerHTML = rows.map((r) => `<li>${pill(r.ok)}<div>${esc(r.label)}<div class="why">${esc(r.detail)}</div></div></li>`).join('');
  $('sigs-t').tBodies[0].innerHTML = v.calls.map((c) => `<tr><td>${esc({ ask: 'Your message', scan: 'Sensitive-item scan' }[c.role] || c.role)}</td><td>${pill(c.hashesOk, 'Yes', 'No')}</td><td class="mono-addr">${esc(c.recovered || 'none')}${c.kind ? ` <span class="hint">${esc(c.kind)}</span>` : ''}</td><td>${pill(c.ok)}</td></tr>`).join('');
  renderCode(v.code, rc);
  $('compose').textContent = v.att.composeHash ? `Enclave app ${v.att.appId}, compose hash ${v.att.composeHash}, key ${v.att.signer}.` : '';

  $('reply-card').hidden = false;
  $('reply-text').textContent = v.reply || '';
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
/* Tooltips: any [data-tip] element. Hover or focus shows it; tapping an (i) toggles it. Kept inside the viewport. */
const tipBox = Object.assign(document.createElement('div'), { id: 'tipbox', className: 'tipbox', hidden: true });
tipBox.setAttribute('role', 'tooltip');
document.body.append(tipBox);
let tipFor = null;
function showTip(el) {
  tipFor = el; tipBox.textContent = el.dataset.tip; tipBox.hidden = false;
  el.setAttribute('aria-describedby', 'tipbox');
  const r = el.getBoundingClientRect(); const w = Math.min(300, window.innerWidth - 24);
  tipBox.style.width = `${w}px`;
  const left = Math.max(12, Math.min(r.left + r.width / 2 - w / 2, window.innerWidth - w - 12));
  const h = tipBox.offsetHeight; const below = r.bottom + 8 + h < window.innerHeight;
  tipBox.style.left = `${left}px`; tipBox.style.top = `${below ? r.bottom + 8 : Math.max(8, r.top - h - 8)}px`;
}
function hideTip() { if (tipFor) tipFor.removeAttribute('aria-describedby'); tipFor = null; tipBox.hidden = true; }
document.addEventListener('pointerover', (e) => { if (e.pointerType !== 'mouse') return; const el = e.target.closest('[data-tip]'); if (el) showTip(el); });
document.addEventListener('pointerout', (e) => { if (e.pointerType === 'mouse' && e.target.closest('[data-tip]') && !e.relatedTarget?.closest?.('[data-tip]')) hideTip(); });
document.addEventListener('focusin', (e) => { const el = e.target.closest('[data-tip]'); if (el && el.matches(':focus-visible')) showTip(el); });
document.addEventListener('focusout', () => hideTip());
document.addEventListener('click', (e) => {
  const it = e.target.closest('.itip');
  if (it) { e.preventDefault(); e.stopPropagation(); showTip(it); return; }
  const g = e.target.closest('#gate li[data-tip]');
  if (g) { showTip(g); return; }
  hideTip();
}, true);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideTip(); });
window.addEventListener('scroll', hideTip, { passive: true });
