// Run the page locally: http://localhost:8787/tools/off-record/
// Serves web/, fetches the shared prompt20 assets (tool.css, splash.css, models-data.js, favicon) from
// prompt20.com, and passes attestation evidence to Intel's and NVIDIA's verifiers, as the
// production nginx does. Keyless sends go to /near/, the stand-in for the demo relay: with NEARAI_KEY set
// it passes the encrypted request to NEAR AI with that key; without it, it answers that the free demo is off.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';
import { intelUrl } from './deps.mjs';

const WEB = fileURLToPath(new URL('../web/', import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const BASE = '/tools/off-record/';
const VERIFY = { gpu: 'https://nras.attestation.nvidia.com/v3/attest/gpu' };
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname === '/' ) { res.writeHead(302, { location: BASE }).end(); return; }
    const ic = url.pathname.match(/^\/tools\/off-record\/intel\/(tcb|qe|pckcrl|rootcrl)(?:\/([A-Za-z0-9]+))?$/);
    if (ic && req.method === 'GET') {
      const target = intelUrl(ic[1], ic[2]);
      if (!target) { res.writeHead(400).end(); return; }
      const r = await fetch(target);
      const keep = ['content-type', 'tcb-info-issuer-chain', 'sgx-enclave-identity-issuer-chain', 'sgx-pck-crl-issuer-chain'];
      res.writeHead(r.status, Object.fromEntries(keep.filter((h) => r.headers.get(h)).map((h) => [h, r.headers.get(h)]))).end(Buffer.from(await r.arrayBuffer()));
      return;
    }
    const v = url.pathname.match(/^\/tools\/off-record\/verify\/(gpu)$/);
    if (v && req.method === 'POST') {
      const chunks = []; let size = 0;
      for await (const c of req) { size += c.length; if (size > 256 * 1024) { res.writeHead(413).end(); return; } chunks.push(c); }
      const r = await fetch(VERIFY[v[1]], { method: 'POST', headers: { 'content-type': 'application/json' }, body: Buffer.concat(chunks) });
      res.writeHead(r.status, { 'content-type': 'application/json' }).end(Buffer.from(await r.arrayBuffer()));
      return;
    }
    const nr = url.pathname.match(/^\/tools\/off-record\/near\/(chat\/completions|signature\/[A-Za-z0-9._:-]+)$/);
    if (nr) {
      if (!process.env.NEARAI_KEY) { res.writeHead(503, { 'content-type': 'application/json' }).end(JSON.stringify({ error: { message: 'The local server has no demo key. Start it with NEARAI_KEY=sk-... npm start, or add your key under Key and model.', relay: true } })); return; }
      const chunks = []; for await (const c of req) chunks.push(c);
      const pass = ['content-type', 'x-signing-algo', 'x-client-pub-key', 'x-model-pub-key', 'x-encryption-version'];
      const headers = { ...Object.fromEntries(pass.filter((h) => req.headers[h]).map((h) => [h, req.headers[h]])), 'x-no-aliasing': 'true', authorization: `Bearer ${process.env.NEARAI_KEY}` };
      const r = await fetch(`https://cloud-api.near.ai/v1/${nr[1]}${url.search}`, { method: req.method, headers, body: req.method === 'POST' ? Buffer.concat(chunks) : undefined });
      res.writeHead(r.status, { 'content-type': r.headers.get('content-type') || 'application/json' });
      for await (const c of r.body) res.write(c);
      res.end();
      return;
    }
    if (url.pathname.startsWith(BASE)) {
      const rel = normalize(url.pathname.slice(BASE.length) || 'index.html');
      if (rel.startsWith('..')) { res.writeHead(400).end(); return; }
      const file = join(WEB, rel);
      res.writeHead(200, { 'content-type': TYPES[extname(file)] || 'application/octet-stream' }).end(await readFile(file));
      return;
    }
    if (['/tools/tool.css', '/tools/splash.css', '/tools/models-data.js', '/favicon.svg'].includes(url.pathname)) {
      const r = await fetch(`https://prompt20.com${url.pathname}`);
      res.writeHead(r.status, { 'content-type': TYPES[extname(url.pathname)] }).end(Buffer.from(await r.arrayBuffer()));
      return;
    }
    res.writeHead(404).end('not found');
  } catch (e) { res.writeHead(500).end(String(e.message || e)); }
}).listen(PORT, process.env.HOST || '127.0.0.1', () => console.log(`Off Record at http://localhost:${PORT}${BASE}`));
