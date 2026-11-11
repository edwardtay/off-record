// Run the page locally: http://localhost:8787/tools/private-prompt/
// Serves web/, fetches the shared prompt20 assets (tool.css, splash.css, models-data.js, favicon) from
// prompt20.com, and passes attestation evidence to Intel's and NVIDIA's verifiers, as the
// production nginx does. No key or prompt ever reaches this server.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const WEB = fileURLToPath(new URL('../web/', import.meta.url));
const PORT = Number(process.env.PORT || 8787);
const BASE = '/tools/private-prompt/';
const VERIFY = { tdx: 'https://cloud-api.phala.network/api/v1/attestations/verify', gpu: 'https://nras.attestation.nvidia.com/v3/attest/gpu' };
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml' };

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (url.pathname === '/' ) { res.writeHead(302, { location: BASE }).end(); return; }
    const v = url.pathname.match(/^\/tools\/private-prompt\/verify\/(tdx|gpu)$/);
    if (v && req.method === 'POST') {
      const chunks = []; let size = 0;
      for await (const c of req) { size += c.length; if (size > 256 * 1024) { res.writeHead(413).end(); return; } chunks.push(c); }
      const r = await fetch(VERIFY[v[1]], { method: 'POST', headers: { 'content-type': 'application/json' }, body: Buffer.concat(chunks) });
      res.writeHead(r.status, { 'content-type': 'application/json' }).end(Buffer.from(await r.arrayBuffer()));
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
}).listen(PORT, () => console.log(`Private Prompt Lab at http://localhost:${PORT}${BASE}`));
