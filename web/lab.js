/* Off Record: a private chat with an AI model in a NEAR AI Cloud enclave. Every message is
   encrypted in this page to the key named in the enclave's hardware quote, every reply is signed by
   that key, and every check is shown. All checks live in engine.js, shared with the Node verifier.
   Imports carry the release tag so a deploy never mixes a cached old module with new ones. */
import { openSession, newReceipt, sendTurn, checkTurns, turnMessages, verifyReceipt, codeChecks, fetchAttestation, privacyKind, newNonce, modelAttestation, callUsage, runAsk, NEARAI, DEFAULT_MODEL } from './engine.js?v=20';
import { SAMPLE_ASK } from './sample.js?v=20';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const fmt = (n) => (n == null || Number.isNaN(n) ? 'n/a' : Number(n).toLocaleString('en-US'));
const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch { /* storage blocked */ } } };

/* Every request has a deadline, so a stalled service shows an error instead of spinning forever.
   Reads (GET) retry twice on a network error, 429 or 5xx; sends (POST) never retry, so a message is
   never sent twice. */
const TIMEOUT_MS = { chat: 180000, other: 30000 };
async function timedFetch(url, opts = {}) {
  const u = String(url); const isGet = !opts.method || opts.method === 'GET';
  const ms = /\/chat\/completions$/.test(u) ? TIMEOUT_MS.chat : TIMEOUT_MS.other;
  for (let attempt = 0; ; attempt++) {
    try {
      // The caller's stop button and the deadline both apply.
      const r = await window.fetch(url, { ...opts, signal: opts.signal ? AbortSignal.any([opts.signal, AbortSignal.timeout(ms)]) : AbortSignal.timeout(ms) });
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
// Without a key of their own, visitors send through prompt20.com's demo relay, which adds a demo key.
const relayDeps = { ...deps, api: new URL('near', location.href).href };

/* Views: the chat or the models table in the main pane; the proof in a side panel; settings in a dialog. */
function showTab(t) {
  $('v-chat').hidden = t === 'models'; $('stage-models').hidden = t !== 'models';
  if (t === 'models') { $('stage-title').textContent = 'Which models are private'; $('stage-sub').textContent = ''; $('verdict').hidden = true; $('demo-note').hidden = true; if (!scanned) scan(); }
  else { $('verdict').hidden = false; }
}
let lastFocus = null;
function showView(t) {
  const open = t === 'proof';
  if (open && !$('proof-panel').hidden) return;
  if (open) lastFocus = document.activeElement;
  $('proof-panel').hidden = !open; $('scrim').hidden = !open;
  document.body.classList.toggle('drawer-open', open);
  if (open) { $('close-proof').focus(); if (lens.browser) playFlow(); }
  else if (lastFocus) { lastFocus.focus?.(); lastFocus = null; }
}
$('verdict').addEventListener('click', () => { if (chat?.rc?.turns?.length) showView('proof'); });
$('close-proof').addEventListener('click', () => showView('chat'));
// "How do I know?": the proof for this chat, or the recorded demo's proof when there is nothing to show yet.
$('how').addEventListener('click', async () => {
  if (!(chat?.rc?.turns?.length && current)) { await loadDemo(); }
  if (chat?.rc?.turns?.length) showView('proof');
});
$('scrim').addEventListener('click', () => showView('chat'));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !$('proof-panel').hidden) showView('chat'); });
$('open-models').addEventListener('click', () => showTab('models'));
function openSettings(msg = '') { $('settings-msg').textContent = msg; $('settings-msg').hidden = !msg; if (!$('settings').open) $('settings').showModal(); if (msg) $('key').focus(); }
$('open-settings').addEventListener('click', () => openSettings());

/* Settings: the key stays in memory unless "Remember on this device" is ticked. */
const savedKey = store.get('offrecord.key');
if (savedKey) { $('key').value = savedKey; $('remember').checked = true; }
const syncKey = () => store.set('offrecord.key', $('remember').checked && $('key').value.trim() ? $('key').value.trim() : null);
$('remember').addEventListener('change', syncKey);
$('key').addEventListener('input', () => { if ($('remember').checked) syncKey(); });
const syncFine = () => { $('fine').textContent = $('key').value.trim() ? 'Encrypted to a sealed enclave before it leaves. Saved only in this browser.' : 'Free demo, up to 20 messages a day. Encrypted to a sealed enclave before it leaves. Saved only in this browser.'; };
$('key').addEventListener('input', syncFine); syncFine();
const savedModel = store.get('offrecord.model');
$('model').addEventListener('change', () => store.set('offrecord.model', $('model').value));

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

if (savedModel && [...$('model').options].some((o) => o.value === savedModel)) $('model').value = savedModel;

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
  // The plain-language summary at the top of the panel follows the same checks.
  const PP = { chip: ['enclave', 'fresh', 'key'], scramble: ['enc'], signed: ['sig', 'shown'] };
  for (const el of $('plain-proof').querySelectorAll('.pp')) {
    const s = PP[el.dataset.pp].map((g) => states[g] || '');
    el.className = `pp ${s.includes('bad') ? 'bad' : s.every((x) => x === 'ok') ? 'ok' : ''}`;
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

const STEP_GATE = { attest: { enclave: 'now' }, vendor: { enclave: 'now', fresh: 'now', key: 'now' }, send: { enclave: 'ok', fresh: 'ok', key: 'ok', enc: 'ok', sig: 'now' } };
const STEP_NOTE = { attest: 'Nothing sent yet.', vendor: 'Nothing sent yet.', send: 'Checks passed. Sent, locked to the enclave.' };
const onStep = (id, msg) => {
  gate(STEP_GATE[id] || {}, `${STEP_NOTE[id] || ''} ${msg}.`);
  const enc = $('flow').querySelector('.node[data-p="enclave"]');
  enc.classList.toggle('checking', id === 'attest' || id === 'vendor');
};

/* Markdown for replies: escaped first, then a small safe subset (headings, lists, tables, code, links). */
function inline(t) {
  return esc(t).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/(^|[^*\w])\*([^*\s][^*]*?)\*(?!\w)/g, '$1<i>$2</i>')
    .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, (_, l, u) => `<a href="${u}" target="_blank" rel="noopener nofollow">${l}</a>`);
}
function md(src) {
  const L = String(src || '').replace(/\r/g, '').split('\n'); let out = ''; let para = [];
  const flush = () => { if (para.length) out += `<p>${para.map(inline).join('<br>')}</p>`; para = []; };
  for (let i = 0; i < L.length; i++) {
    const l = L[i];
    if (/^```/.test(l)) { flush(); const code = []; for (i++; i < L.length && !/^```/.test(L[i]); i++) code.push(L[i]); out += `<pre><code>${esc(code.join('\n'))}</code></pre>`; continue; }
    const h = /^(#{1,6})\s+(.*)$/.exec(l);
    if (h) { flush(); out += `<h${Math.min(6, h[1].length + 2)}>${inline(h[2])}</h${Math.min(6, h[1].length + 2)}>`; continue; }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(l)) { flush(); out += '<hr>'; continue; }
    if (/^\s*\|.*\|\s*$/.test(l) && /^\s*\|?[\s:|-]+\|?\s*$/.test(L[i + 1] || '') && /-/.test(L[i + 1] || '')) {
      flush(); const row = (r) => r.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      const head = row(l); const body = []; for (i += 2; i < L.length && /^\s*\|.*\|\s*$/.test(L[i]); i++) body.push(row(L[i])); i--;
      out += `<div class="mdt"><table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${body.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
      continue;
    }
    const li = /^\s*([-*+]|\d+[.)])\s+(.*)$/.exec(l);
    if (li) {
      flush(); const ordered = /\d/.test(li[1]); const items = [];
      for (; i < L.length; i++) { const m = /^\s*([-*+]|\d+[.)])\s+(.*)$/.exec(L[i]); if (m) items.push(m[2]); else if (/^\s{2,}\S/.test(L[i]) && items.length) items[items.length - 1] += ` ${L[i].trim()}`; else break; }
      i--; out += `<${ordered ? 'ol' : 'ul'}>${items.map((x) => `<li>${inline(x)}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`; continue;
    }
    if (!l.trim()) { flush(); continue; }
    para.push(l);
  }
  flush();
  return out;
}

/* Attachments: read in this page and sent inside the encrypted message. */
const ATTACH_MAX = 120000;
let attachments = [];
const attachBlock = (a) => `\n\n[Attached: ${a.name}]\n${a.text}\n[End of ${a.name}]`;
const ATTACH_RE = /\n\n\[Attached: (.+?)\]\n([\s\S]*?)\n\[End of \1\]/g;
async function pdfText(file) {
  const pdfjs = await import('./vendor/pdfjs/pdf.min.js');
  pdfjs.GlobalWorkerOptions.workerSrc = new URL('vendor/pdfjs/pdf.worker.min.js', import.meta.url).href;
  const doc = await pdfjs.getDocument({ data: new Uint8Array(await file.arrayBuffer()), isEvalSupported: false }).promise;
  const pages = [];
  for (let p = 1; p <= doc.numPages; p++) { const c = await (await doc.getPage(p)).getTextContent(); pages.push(c.items.map((x) => x.str + (x.hasEOL ? '\n' : ' ')).join('')); }
  return pages.join('\n\n').replace(/[ \t]+\n/g, '\n').trim();
}
function renderAttachments() {
  $('attach-list').innerHTML = attachments.map((a, i) => `<span class="chip file-chip">${esc(a.name)} <span class="sub">${fmt(a.text.length)} characters${a.cut ? ', cut to fit' : ''}</span><button type="button" class="link" data-rm="${i}" aria-label="Remove ${esc(a.name)}">Remove</button></span>`).join('');
}
$('attach-list').addEventListener('click', (e) => { const b = e.target.closest('[data-rm]'); if (b) { attachments.splice(Number(b.dataset.rm), 1); renderAttachments(); } });
$('attach').addEventListener('change', async (ev) => {
  for (const f of ev.target.files) {
    try {
      let text = /\.pdf$/i.test(f.name) || f.type === 'application/pdf' ? await pdfText(f) : await f.text();
      if (!text.trim()) throw new Error('no text found (a scanned PDF has none)');
      const cut = text.length > ATTACH_MAX; if (cut) text = text.slice(0, ATTACH_MAX);
      attachments.push({ name: f.name, text, cut });
    } catch (e) { fail(`Could not read ${f.name}: ${e.message}`); }
  }
  ev.target.value = ''; renderAttachments();
});

/* Starters: a few sensitive jobs people bring to a private chat. Each sets the chat's instructions. */
const STARTERS = [
  { label: 'Explain my lab results', system: SAMPLE_ASK.system, hint: 'Paste or attach your results' },
  { label: 'Review a contract', system: 'You review contracts for someone who is not a lawyer. Explain each clause in plain English, flag terms that are unusual or one-sided, and list what to ask before signing. Say when a lawyer is needed.', hint: 'Paste or attach the contract' },
  { label: 'Sort out my finances', system: 'You help with personal finances: debts, budgets, salary and tax questions. Use the numbers given, be concrete, and say when a professional is needed.', hint: 'Describe your situation, with the numbers' },
  { label: 'Talk something through', system: 'You are a calm, thoughtful listener. Help the person think through something personal. Ask one question at a time, and suggest professional help if they mention a risk of harm.', hint: 'What is on your mind?' },
];
function renderStarters() {
  const show = !!chat && !chat.demo && !chat.rc?.turns?.length && !chat.pending;
  $('starters').hidden = !show; $('samples').hidden = !show;
  if (!show) return;
  $('starters').innerHTML = STARTERS.map((s, i) => `<button type="button" class="chip starter" data-st="${i}" aria-pressed="${$('system').value === s.system}">${esc(s.label)}</button>`).join('');
}
$('starters').addEventListener('click', (e) => {
  const b = e.target.closest('[data-st]'); if (!b) return;
  const s = STARTERS[Number(b.dataset.st)];
  $('system').value = $('system').value === s.system ? '' : s.system;
  $('msg').placeholder = $('system').value ? s.hint : 'Message the enclave';
  renderStarters(); $('msg').focus();
});

/* Fictional sample files, so anyone can try an attachment without real data. */
const SAMPLES = {
  lab: { file: 'samples/lab-report.pdf', starter: 0, ask: 'Here are my latest blood test results. What stands out, and what should I ask my doctor?' },
  bank: { file: 'samples/bank-statement.pdf', starter: 2, ask: 'Here is my bank statement for October. Sort my spending into categories and flag anything unusual.' },
};
$('samples').addEventListener('click', async (e) => {
  const b = e.target.closest('[data-sample]'); if (!b) return;
  const s = SAMPLES[b.dataset.sample]; const name = s.file.split('/').pop();
  try {
    if (!attachments.some((a) => a.name === name)) {
      const blob = await (await timedFetch(s.file)).blob();
      attachments.push({ name, text: await pdfText(new File([blob], name, { type: 'application/pdf' })), cut: false });
      renderAttachments();
    }
    const st = STARTERS[s.starter]; $('system').value = st.system;
    $('msg').value = s.ask; grow(); renderStarters(); $('msg').focus();
  } catch (err) { fail(`Could not load the sample: ${err.message}`); }
});

/* Saved chats: IndexedDB in this browser. Each record is the full receipt. */
const DB = {
  db: null,
  open() {
    if (!this.db) this.db = new Promise((ok, no) => { const r = indexedDB.open('off-record', 1); r.onupgradeneeded = () => r.result.createObjectStore('chats', { keyPath: 'id' }); r.onsuccess = () => ok(r.result); r.onerror = () => no(r.error); });
    return this.db;
  },
  async run(mode, fn) { const db = await this.open(); return new Promise((ok, no) => { const t = db.transaction('chats', mode); const req = fn(t.objectStore('chats')); t.oncomplete = () => ok(req?.result); t.onerror = () => no(t.error); t.onabort = () => no(t.error); }); },
  all() { return this.run('readonly', (st) => st.getAll()).catch(() => null); },
  put(c) { return this.run('readwrite', (st) => st.put(c)); },
  del(id) { return this.run('readwrite', (st) => st.delete(id)); },
};
const titleOf = (text) => { const first = String(text).replace(ATTACH_RE, '').trim().split('\n')[0] || 'Attached file'; if (first.length <= 60) return first; const cut = first.slice(0, 60); return cut.slice(0, cut.lastIndexOf(' ') > 30 ? cut.lastIndexOf(' ') : 60); };
async function renderChatList() {
  const all = await DB.all();
  if (all === null) { $('chat-list').innerHTML = '<li class="muted">This browser blocks storage, so chats are not saved.</li>'; return; }
  all.sort((a, b) => b.updated.localeCompare(a.updated));
  const demoLi = `<li class="${chat?.id === 'demo' ? 'on' : ''}"><button type="button" class="chat-open" data-demo="1"><b>Demo: a private health question</b><span class="sub">Recorded, checked live</span></button></li>`;
  $('chat-list').innerHTML = demoLi + (all.length ? all.map((c) => `<li class="${chat?.id === c.id ? 'on' : ''}"><button type="button" class="chat-open" data-id="${esc(c.id)}"><b>${esc(c.title)}</b><span class="sub">${esc(new Date(c.updated).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }))} </span></button><button type="button" class="link chat-del" data-del="${esc(c.id)}" aria-label="Delete this chat">Delete</button></li>`).join('') : '<li class="muted">Your chats appear here, saved only in this browser.</li>');
}
$('chat-list').addEventListener('click', async (e) => {
  const d = e.target.closest('[data-del]');
  if (d) { if (!confirm('Delete this chat from this browser? This cannot be undone.')) return; await DB.del(d.dataset.del); if (chat?.id === d.dataset.del) startChat(); renderChatList(); return; }
  if (e.target.closest('[data-demo]') && !sending) { loadDemo(); return; }
  const o = e.target.closest('[data-id]');
  if (o && !sending) { const all = await DB.all(); const c = (all || []).find((x) => x.id === o.dataset.id); if (c) openSaved(c); }
});
const saveChat = async () => { if (!chat || chat.demo || !chat.rc?.turns?.length) return; try { await DB.put({ id: chat.id, title: chat.title, updated: new Date().toISOString(), rc: chat.rc, relay: !!chat.relay }); } catch { /* storage full or blocked */ } renderChatList(); };

/* The conversation. */
let chat = null; let sending = null; let opId = 0;
const signerOf = (rc) => { const m = modelAttestation(rc.attestation, rc.model); return m.signing_public_key || m.signing_address; };
function fail(m) { $('run-error').textContent = m; $('run-error').hidden = !m; }
function userHtml(text) {
  const files = []; const body = String(text).replace(ATTACH_RE, (_, name, t) => { files.push([name, t]); return ''; }).trim();
  return `${body ? `<div class="utext">${esc(body)}</div>` : ''}${files.map(([n, t]) => `<details class="afile"><summary>File: ${esc(n)} <span class="sub">${fmt(t.length)} characters</span></summary><pre>${esc(t)}</pre></details>`).join('')}`;
}
function badge(t, i) {
  if (!t) return '<span class="vbtn">Checking</span>';
  return `<button type="button" class="vbtn ${t.ok ? 'ok' : 'bad'}" data-turn="${i}" data-tip="${t.ok ? 'Signed by the enclave\'s key over the exact encrypted bytes. Click for the proof.' : 'This reply failed a check. Click for details.'}">${t.ok ? 'Verified' : 'Not verified'}</button>`;
}
function renderThread() {
  const th = $('thread');
  if (!chat?.rc?.turns?.length && !chat?.pending) { th.innerHTML = chat?.demo ? '' : `<div class="empty"><span class="logo big"><svg class="ic" aria-hidden="true"><use href="#i-lab"/></svg></span><h2>What do you want to keep off the record?</h2><p>Only a sealed enclave can read this chat. Every reply is checked before you see it.</p></div>`; renderStarters(); return; }
  const rows = [];
  const turns = chat.rc?.turns || [];
  turns.forEach((m, i) => {
    rows.push(`<div class="msg user"><div class="bubble">${userHtml(m)}</div></div>`);
    rows.push(`<div class="msg ai"><div class="bubble md">${md(chat.view?.replies?.[i] ?? '')}</div><div class="meta">${badge(chat.view?.perTurn?.[i], i)}</div></div>`);
  });
  if (chat.pending) {
    rows.push(`<div class="msg user"><div class="bubble">${userHtml(chat.pending.message)}</div></div>`);
    rows.push(`<div class="msg ai"><div class="bubble md streaming" id="live">${chat.pending.text ? md(chat.pending.text) : `<span class="muted">${esc(chat.pending.status || 'Waiting for the enclave')}</span>`}</div></div>`);
  }
  const near = th.scrollHeight - th.scrollTop - th.clientHeight < 80;
  th.innerHTML = rows.join('');
  if (near || chat.pending) th.scrollTop = th.scrollHeight;
  renderStarters();
}
let liveFrame = 0;
function renderLive() {
  if (liveFrame) return;
  liveFrame = requestAnimationFrame(() => {
    liveFrame = 0; const el = $('live'); if (!el || !chat?.pending) return;
    const th = $('thread'); const near = th.scrollHeight - th.scrollTop - th.clientHeight < 80;
    el.innerHTML = md(chat.pending.text); if (near) th.scrollTop = th.scrollHeight;
  });
}
$('thread').addEventListener('click', (e) => { const b = e.target.closest('.vbtn'); if (b) { lensTurn = Number(b.dataset.turn); hideTip(); if (current) { lens = lensData(chat.rc, current, lensTurn); } showView('proof'); playFlow(); } });

function startChat() {
  if (sending) return;
  opId++;
  chat = { id: `c${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, title: 'New chat', rc: null, session: null, view: null, demo: false };
  current = null; lens = {}; lensText = ''; lensTurn = null;
  if ($('system').disabled) $('system').value = '';
  $('demo-note').hidden = true; $('system').disabled = false; $('system-hint').textContent = '';
  $('stage-title').textContent = 'New chat'; $('stage-sub').textContent = ''; $('verdict').className = 'status idle'; $('verdict').textContent = '';
  gate({}, 'Nothing sent yet. The enclave is checked before your first message leaves.');
  $('code-card').hidden = true; $('proof').innerHTML = ''; $('sigs-t').tBodies[0].innerHTML = ''; $('break-out').innerHTML = '';
  fail(''); showTab('chat'); showView('chat'); renderThread(); renderChatList(); $('msg').focus();
}
$('new-chat').addEventListener('click', startChat);

async function openReceipt(rc, { id, title, demo = false, relay = false, note = '' } = {}) {
  if (sending) return;
  const op = ++opId;
  chat = { id: id || `c${Date.now().toString(36)}`, title: title || note || 'Receipt', rc, session: null, view: null, demo, relay };
  current = null; lens = {}; lensText = ''; lensTurn = null;
  $('demo-note').hidden = !demo; showTab('chat');
  $('stage-title').textContent = chat.title; $('stage-sub').textContent = ''; $('verdict').className = 'status'; $('verdict').textContent = 'Checking';
  fail(''); gate({}, 'Checking the recorded chat with Intel, NVIDIA and NEAR AI.');
  if (!demo) { $('system').value = rc.system || ''; $('system').disabled = true; $('system-hint').textContent = 'Fixed for this chat: every turn is checked against it.'; }
  else { $('system').disabled = false; $('system-hint').textContent = ''; }
  try {
    chat.view = await checkTurns(rc, signerOf(rc), deps);
    if (op !== opId) return;
    chat.rc = chat.view.rc;
    renderThread();
    const v = await verifyReceipt(rc, deps);
    if (op !== opId) return;
    chat.view = v; render(v, note);
  } catch (e) {
    if (op !== opId) return;
    fail(e.message); $('verdict').textContent = 'Not checked'; $('verdict').className = 'status bad'; renderThread();
  }
  renderChatList();
}
const openSaved = (c) => { showTab('chat'); showView('chat'); openReceipt(c.rc, { id: c.id, title: c.title, relay: !!c.relay, note: 'Saved chat, checked again' }); };
$('receipt-file').addEventListener('change', async (ev) => {
  const f = ev.target.files[0]; if (!f) return; ev.target.value = '';
  let rc; try { rc = JSON.parse(await f.text()); } catch { fail('That file is not valid JSON.'); return; }
  if (!rc?.attestation || !Array.isArray(rc.calls)) { fail('That file is not an Off Record receipt.'); return; }
  openReceipt(rc, { title: `Receipt ${f.name}`, note: `Receipt ${f.name}` });
});

function setSending(on) {
  $('send').innerHTML = `<svg class="ic" aria-hidden="true"><use href="#${on ? 'i-stop' : 'i-send'}"/></svg><span id="send-label" class="sr">${on ? 'Stop' : 'Send'}</span>`;
  $('send').setAttribute('aria-label', on ? 'Stop the reply' : 'Send'); $('send').classList.toggle('stop', on);
}
/* The message box grows with its text, up to a limit. */
function grow() { const t = $('msg'); t.style.height = 'auto'; t.style.height = `${Math.min(t.scrollHeight, 220)}px`; }
$('msg').addEventListener('input', grow);
/* Send one message: check the enclave first if this chat has no live session, then stream the reply. */
async function send() {
  if (sending) { sending.abort(); return; }
  const text = $('msg').value.trim();
  if (!text && !attachments.length) return;
  const key = $('key').value.trim();
  const via = key ? deps : relayDeps;
  if (!chat || chat.demo || (chat.rc && chat.rc.model !== $('model').value && !chat.rc.turns.length)) startChat();
  if (chat.rc && chat.rc.model !== $('model').value) { fail(`This chat runs on ${chat.rc.model}. Start a new chat to use ${$('model').value}.`); return; }
  fail('');
  const message = text + attachments.map(attachBlock).join('');
  const op = opId;
  sending = new AbortController();
  setSending(true); $('msg').value = ''; grow(); const sentFiles = attachments; attachments = []; renderAttachments();
  chat.pending = { message, text: '', status: chat.session ? 'Encrypting to the enclave key' : 'Checking the enclave before anything is sent' };
  renderThread();
  try {
    if (!chat.session) {
      $('verdict').className = 'status'; $('verdict').textContent = 'Checking';
      const session = await openSession({ model: $('model').value, onStep: (id, msg) => { onStep(id, msg); chat.pending.status = msg; renderThread(); } }, deps);
      if (op !== opId) return;
      if (chat.rc && signerOf(chat.rc) !== session.signer) throw new Error('The enclave has a new key since this chat started, so it cannot continue. Start a new chat.');
      chat.session = session;
      if (!chat.rc) { chat.rc = newReceipt(session, $('system').value); chat.title = titleOf(message); $('system').disabled = true; $('system-hint').textContent = 'Fixed for this chat: every turn is checked against it.'; }
      chat.code = codeChecks(session.attestation, session.nonce, session.model, deps).catch(() => null);
    }
    onStep('send', 'Streaming the reply, encrypted to this page');
    chat.pending.status = 'Waiting for the enclave';
    const replies = chat.view?.replies || [];
    await sendTurn({ key: key || 'demo', session: chat.session, rc: chat.rc, replies, message, signal: sending.signal, onDelta: (d) => { chat.pending.text += d; renderLive(); } }, via);
    if (!key) chat.relay = true;
    if (op !== opId) return;
    const last = chat.rc.calls.find((c) => c.role === `turn-${chat.rc.turns.length - 1}`);
    if (last?.stopped) {
      const i = chat.rc.turns.length - 1; chat.rc.turns.pop(); chat.rc.calls = chat.rc.calls.filter((c) => !c.role.endsWith(`-${i}`));
      chat.pending = null; $('msg').value = text; grow(); attachments = sentFiles; renderAttachments();
      fail('Stopped. Nothing from that reply was kept, and your message is back in the box.');
    } else {
      chat.pending = null;
      $('stage-title').textContent = chat.title;
      gate({ ...STEP_GATE.send }, 'Checking the signature and opening every encrypted field.');
      chat.view = await checkTurns(chat.rc, chat.session.signer, deps);
      const att = chat.session.att; const t = chat.view;
      const code = await chat.code;
      const v = { ok: att.rows.every((r) => r.ok) && code?.compose?.ok === true && t.calls.every((c) => c.ok) && t.structure.every((r) => r.ok), att, code, calls: t.calls, structure: t.structure, perTurn: t.perTurn, replies: t.replies, sensitive: t.sensitive };
      if (op !== opId) return;
      chat.view = v; render(v, 'Live chat'); saveChat();
    }
  } catch (e) {
    if (op !== opId) return;
    chat.pending = null; $('msg').value = text; grow(); attachments = sentFiles; renderAttachments();
    gate({}, ''); fail(e.message);
    if (!chat.rc?.turns?.length) { $('verdict').textContent = 'Not sent'; $('verdict').className = 'status'; }
  } finally {
    if (op === opId) { sending = null; setSending(false); renderThread(); }
    else { sending = null; setSending(false); }
  }
}
$('composer').addEventListener('submit', (e) => { e.preventDefault(); send(); });
$('msg').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && window.matchMedia('(pointer:fine)').matches) { e.preventDefault(); send(); } });

/* Who can read it: the parties on the path (and two off it), and a lens that shows exactly what the
   chosen party sees for one turn, from the real request and reply bytes. */
const HEX = '0123456789abcdef';
let lens = {}; let lensRun = 0; let lensText = ''; let flowRun = 0; let lensTurn = null;
function standardRequest(msgs) { return JSON.stringify({ model: 'any-model', messages: msgs }, null, 1); }
function lensData(rc, v, i = null) {
  const n = rc.turns.length; const k = i == null ? n - 1 : i;
  const call = rc.calls.find((c) => c.role === `turn-${k}`) || rc.calls[0];
  const msgs = turnMessages(rc.system, rc.turns, v.replies || [], k);
  const plain = msgs.map((m) => `[${m.role === 'system' ? 'instructions' : m.role === 'user' ? 'you' : 'assistant'}]\n${m.content}`).join('\n\n');
  let body = call.request; try { body = JSON.stringify(JSON.parse(call.request), null, 1); } catch { /* keep raw */ }
  const reply = v.replies?.[k] || '';
  const key = String(v.att.signer || '').slice(0, 12);
  const marks = v.perTurn?.flatMap((t) => t.sensitive || []) || [];
  const which = n > 1 ? ` (message ${k + 1} of ${n})` : '';
  return {
    browser: { title: `What your browser sees${which}`, text: plain, marks, note: marks.length ? `Readable only here and inside the enclave. Highlighted: sensitive items the enclave found.` : 'Readable only here and inside the enclave.' },
    gateway: { title: `What NEAR AI's gateway sees${which}`, text: body, hex: true, note: chat?.relay ? 'The exact request it received, with the whole conversation so far. Your words are gibberish; the model name, size and timing are not. It came from prompt20.com\'s demo relay, so it never saw your IP.' : 'The exact request it received, with the whole conversation so far. Your words are gibberish; the model name, size, timing, IP and API key are not.' },
    enclave: { title: `What the secure enclave sees${which}`, marks, text: plain + (reply ? `\n\n[its reply, locked back to your browser]\n${reply.slice(0, 800)}${reply.length > 800 ? ' ...' : ''}` : ''), note: `Unlocked inside the enclave with key ${key}..., the one in its hardware proof.` },
    api: { title: `What a standard AI API receives${which}`, text: standardRequest(msgs), plainHit: true, marks, note: 'The same conversation sent the usual way. TLS protects it on the way, then the provider reads every word and keeps it under its own retention policy.' },
    prompt20: chat?.relay
      ? { title: `What prompt20.com's demo relay sees${which}`, text: body, hex: true, note: 'This chat used the free demo, so it passed through prompt20.com, which added the demo key. It sees the same ciphertext as NEAR AI\'s gateway, plus your IP. It cannot unlock your words or change a reply without breaking the signature.' }
      : { title: 'What prompt20.com sees', text: '', note: 'Nothing from this page. Your messages and key go only to NEAR AI; prompt20.com only relays public evidence (Intel\'s signed collateral, the GPU evidence).' },
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

/* Readable in transit, over the whole chat: measured on the real request bytes, against the same chat
   sent the usual way. */
function leakCount(plain, wireText) {
  // Count message characters that appear in the request bytes in runs of 6 or more (words, numbers, names).
  let leaked = 0; const W = 6;
  for (let i = 0; i + W <= plain.length;) {
    if (wireText.includes(plain.slice(i, i + W))) { let j = i + W; while (j < plain.length && wireText.includes(plain.slice(i, j + 1))) j++; leaked += j - i; i = j; } else i++;
  }
  return leaked;
}
function meter(rc, v) {
  const plain = rc.turns.join('\n');
  const readable = (body) => { try { return JSON.parse(body).messages.map((m) => m.content).join('\n'); } catch { return body; } };
  const e2eeOk = v.structure.find((r) => r.id === 'e2ee')?.ok === true;
  const wire = rc.calls.map((c) => readable(c.request)).join('\n');
  const items = v.sensitive || [];
  if (items.length) {
    const byType = {}; for (const it of items) byType[it.type] = (byType[it.type] || 0) + 1;
    const here = e2eeOk ? 0 : items.filter((it) => wire.includes(it.text)).length;
    $('sens-chips').innerHTML = `<b class="${here ? 'badc' : 'okc'}">${here} of ${items.length}</b> sensitive items here, <b class="badc">${items.length} of ${items.length}</b> with a standard AI API: ${Object.entries(byType).map(([t, n]) => `<span class="chip">${esc(t)}${n > 1 ? ` x${n}` : ''}</span>`).join('')}`;
  } else {
    const n = plain.length; const here = e2eeOk ? 0 : leakCount(plain, wire);
    $('sens-chips').innerHTML = `<b class="${here ? 'badc' : 'okc'}">${fmt(here)} of ${fmt(n)}</b> characters here, <b class="badc">${fmt(n)} of ${fmt(n)}</b> with a standard AI API`;
  }
}
/* This chat's cost in NEAR AI credits, from its real token usage and NEAR AI's published prices. */
let pricing = null;
async function costLine(rc) {
  const el = $('cost-line'); el.hidden = true;
  try {
    pricing = pricing || Object.fromEntries((await (await timedFetch(`${NEARAI}/models`)).json()).data.map((m) => [m.id, m.pricing]));
    const pr = pricing[rc.model]; if (!pr) return;
    let usd = 0;
    for (const c of rc.calls) { const u = callUsage(c); usd += ((u.prompt_tokens || 0) * pr.input + (u.completion_tokens || 0) * pr.output) / 1e6; }
    if (chat?.rc !== rc) return;
    el.hidden = false;
    el.innerHTML = `Cost so far <b>$${usd < 0.01 ? usd.toFixed(4) : usd.toFixed(2)}</b> in NEAR AI credits, payable with <a href="https://docs.near.ai/cloud/staking-for-inference/overview" target="_blank" rel="noopener">NEAR staking</a> <button type="button" class="itip" data-tip="${rc.calls.length} call${rc.calls.length === 1 ? '' : 's'}, priced from their real token usage and NEAR AI's published prices. Staking for Inference pays credits from NEAR staking rewards, and the stake stays yours." aria-label="What is this?">i</button>`;
  } catch { /* prices unavailable */ }
}
$('replay-flow').addEventListener('click', playFlow);

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
  const intelTxt = (x, sig) => `Intel's signature ${sig ? 'checks out here' : 'FAILS here'}${pending(x) ? '' : x ? ', and Intel\'s collateral lists the platform as trusted and not revoked' : ', but Intel\'s collateral check failed'}${pending(x) ? '; Intel\'s collateral could not be fetched, so this link is not confirmed' : ''}`;
  const links = [
    { ok: c.ok, title: 'The enclave booted this compose file', body: c.ok ? `${esc(c.name)}: its sha256 is in the hardware quote twice (MRCONFIGID and the RTMR3 event log). It pins ${c.images.map((i) => `<code>${esc(short(i))}</code>`).join(', ')}.` : 'The compose file does not match the quote.' },
    { ok: d.ok && d.intel === true, mid: d.ok && pending(d.intel), title: 'NEAR AI\'s deploy log, signed by the same enclave', body: d.present ? `${d.entries} deploy actions. Their hash and this run's nonce are in a second TDX quote from the same VM (same MRTD and RTMRs). ${intelTxt(d.intel, d.sig)}.` : 'No deploy log in this proof.' },
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
  links.push({ ok: g.ok && g.intel === true, mid: g.ok && pending(g.intel), title: 'NEAR AI\'s gateway runs in its own enclave', body: g.present ? `The gateway that relays your ciphertext: ${g.compose.images.filter((i) => /cloud-api/.test(i)).map((i) => `<code>${esc(short(i))}</code>`).join('') || esc(g.compose.name)}. Its quote names its key and this run's nonce, and its compose file matches. ${intelTxt(g.intel, g.sig)}.` : 'No gateway proof in this run.' });
  const okN = links.filter((l) => l.ok).length;
  $('code-sum').className = `pill ${okN === links.length ? 'ok' : 'bad'}`;
  $('code-sum').textContent = `${okN} of ${links.length} linked`;
  $('code-chain').innerHTML = links.map((l) => `<li class="${l.ok ? 'ok' : l.mid ? 'mid' : 'bad'}"><b>${esc(l.title)}</b><div>${l.body}</div></li>`).join('');
  card.hidden = false;
}
const pill = (ok, yes = 'Pass', no = 'Fail') => `<span class="pill ${ok ? 'ok' : 'bad'}">${ok ? yes : no}</span>`;
const ROLE_NAME = (r) => { const m = /^(turn|scan)-(\d+)$/.exec(r); return m ? (m[1] === 'turn' ? `Message ${Number(m[2]) + 1}` : `Sensitive-item scan ${Number(m[2]) + 1}`) : r; };
function render(v, note) {
  current = v;
  const rc = chat.rc;
  const vd = $('verdict');
  vd.className = `status ${v.ok ? 'ok' : 'bad'}`;
  vd.textContent = v.ok ? 'Verified' : v.unreachable ? 'Not verified: a check could not run' : 'Not verified';
  $('stage-title').textContent = chat.title;
  $('stage-sub').textContent = `${rc.model} · ${new Date(rc.created).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}`;
  gate(gateFrom(v), v.ok ? `All six checks passed, for ${rc.turns.length === 1 ? 'the message' : `all ${rc.turns.length} messages`}.` : 'A check failed. Details below.', !chat.animated);
  chat.animated = true;
  lens = lensData(rc, v, lensTurn);
  const p20 = $('flow').querySelector('.node[data-p="prompt20"]');
  p20.classList.toggle('none', !chat?.relay); p20.classList.toggle('cipher', !!chat?.relay);
  p20.querySelector('.nv').textContent = chat?.relay ? 'Ciphertext (demo relay)' : 'Not on the path';
  p20.dataset.tip = chat?.relay ? 'This chat used the free demo, so prompt20.com relayed the ciphertext and added the demo key. It cannot unlock it.' : 'This site is not on the path. Your key and message go straight from your browser to NEAR AI.';
  meter(rc, v);
  costLine(rc);
  if (!$('proof-panel').hidden) playFlow(); else lensText = '';
  $('break-out').innerHTML = '';
  const rows = [...v.att.rows, ...v.structure];
  $('proof').innerHTML = rows.map((r) => `<li>${pill(r.ok)}<div>${esc(r.label)}<div class="why">${esc(r.detail)}</div></div></li>`).join('');
  $('sigs-t').tBodies[0].innerHTML = v.calls.map((c) => `<tr><td>${esc(ROLE_NAME(c.role))}</td><td>${pill(c.hashesOk, 'Yes', 'No')}</td><td class="mono-addr">${esc(c.recovered || 'none')}${c.kind ? ` <span class="hint">${esc(c.kind)}</span>` : ''}</td><td>${pill(c.ok)}</td></tr>`).join('');
  renderCode(v.code, rc);
  $('compose').textContent = v.att.composeHash ? `Enclave app ${v.att.appId}, compose hash ${v.att.composeHash}, key ${v.att.signer}.` : '';
  renderThread();
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
  if (!chat?.rc?.turns?.length) return;
  showView('proof');
  const rc = structuredClone(chat.rc);
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
  const c = [...rc.calls].reverse().find((x) => /^(turn-|ask)/.test(x.role));
  const m = /"content":"[0-9a-f]/.exec(c.response); const i = m.index + 12;
  c.response = c.response.slice(0, i) + (c.response[i] === 'a' ? 'b' : 'a') + c.response.slice(i + 1);
  return 'one character of an encrypted reply changed.';
}));
$('wrongkey').addEventListener('click', () => attack('Use a fake lock', (rc) => {
  const m = modelAttestation(rc.attestation, rc.model);
  const fake = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
  m.signing_public_key = fake; m.signing_address = fake;
  return 'a lock the enclave never signed.';
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
  if (!chat?.rc?.turns?.length || sending) return;
  $('fresh').disabled = true;
  const { session, code } = chat;
  try { await openReceipt(chat.rc, { id: chat.id, title: chat.title, demo: chat.demo, relay: chat.relay, note: 'Checked again' }); } finally { $('fresh').disabled = false; }
  if (session) { chat.session = session; chat.code = code; }
});
$('download').addEventListener('click', () => {
  if (!chat?.rc?.turns?.length) return;
  if (!confirm('This receipt contains the secrets that open its messages. Anyone you give it to can read the whole chat. Download it?')) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(chat.rc)], { type: 'application/json' }));
  a.download = `off-record-receipt-${chat.rc.created.slice(0, 19).replace(/[:T]/g, '-')}.json`;
  a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

/* First view: a real recorded chat, checked live, before any input. */
let demoRc = null;
async function loadDemo() {
  try { demoRc = demoRc || await (await timedFetch('sample-chat.json')).json(); await openReceipt(structuredClone(demoRc), { id: 'demo', title: 'Demo: a private health question', demo: true, note: 'Recorded demo' }); }
  catch (e) { fail(`Could not load the demo: ${e.message}`); }
}
renderChatList(); loadDemo();

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

/* Phones: the chat list folds into the top bar. */
$('side-toggle').addEventListener('click', () => { const s = document.querySelector('.side'); const open = !s.classList.contains('open'); s.classList.toggle('open', open); $('side-toggle').setAttribute('aria-expanded', String(open)); });
document.querySelector('.side').addEventListener('click', (e) => { if (e.target.closest('.chat-open, #new-chat') && window.matchMedia('(max-width:860px)').matches) { document.querySelector('.side').classList.remove('open'); $('side-toggle').setAttribute('aria-expanded', 'false'); } });
