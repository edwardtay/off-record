# Off Record

A private AI chat where you can check the privacy yourself. Your message is locked in your browser so that only the sealed enclave running the AI can read it, and every reply carries the signature of the key inside that enclave. Before your message leaves, your browser checks Intel's and NVIDIA's proof of the enclave. Chat history stays on your device.

**Why now.** NEAR AI is retiring its own Private Chat: it became read-only on 28 Sep 2026 and private.near.ai shuts down on 15 Nov 2026, deleting the conversation history it stored on NEAR's servers ([shutdown notice in its source](https://github.com/nearai/private-chat/blob/main/src/components/common/SunsetBanner.tsx)). The suggested replacement, the NEAR AI Cloud Playground, keeps no history at all. Brave Leo also runs on NEAR AI's enclaves; [Brave's announcement](https://brave.com/blog/browser-ai-e2ee/) (15 Oct 2026) says the browser relies on Brave's gateway for the enclave check today, with checking in the browser to come. Off Record is a chat people can keep using: history on the device, every proof checked in the browser.

- **A real chat.** Follow-up questions, streamed replies, and attachments (PDF, text, Markdown, CSV, JSON) read in the page and sent encrypted like the message. Starters for the jobs people bring to a private chat: lab results, a contract, money, something personal. Fictional sample files let anyone try it without real data.
- **History stays on your device.** Saved chats are kept only in the browser (IndexedDB). Each new message re-sends the earlier turns to the enclave, encrypted like the message itself. Each saved chat is a full receipt, so opening it re-checks every proof.
- **Proof that holds up.** Intel's DCAP check (quote signature chain, TCB status, quoting enclave, revocation, from Intel's signed collateral) runs in the page before your first message leaves. NVIDIA's verifier evaluates the GPU evidence and the page checks NVIDIA's signature on its answer. Every reply's signature is checked in the page. Turn 2 is checked to have carried exactly turn 1 and its signed reply, so the conversation shown is the conversation the enclave saw.
- **The page itself can be checked.** `npm run check-live` fetches each file of the page in `web/` from prompt20.com and compares it with this repository, so the scripts doing the checking are the published ones.

**Live:** https://prompt20.com/tools/off-record/

## For judges: 2 minutes

[![test](https://github.com/edwardtay/off-record/actions/workflows/test.yml/badge.svg)](https://github.com/edwardtay/off-record/actions/workflows/test.yml)

In the browser: open the [live page](https://prompt20.com/tools/off-record/) and wait for the **Verified** pill to turn green. Click it, then press each **Try to break it** button; each is refused and names the check that caught it.

On the command line (Node 20+, no key needed):

```
npm install
npm test               # 29 offline tests, all pass
npm run verify         # asks Intel, NVIDIA and NEAR AI now about the recorded chat; ends with VERIFIED
npm run tamper         # flips one byte of a signed reply; signature, decryption and chat checks FAIL; NOT VERIFIED
npm run swap-message   # rewrites an earlier message; "The chat shown is the one signed" FAILs; NOT VERIFIED
npm run check-live     # hashes every file served at prompt20.com against web/; MATCH on each
```

## Try it (no key, no sign-up)

1. Open https://prompt20.com/tools/off-record/. The recorded demo chat re-checks itself live; the **Verified** pill at the top turns green.
2. Click **Verified** (or **How do I know?** under the message box). The proof panel opens with three plain answers: only the sealed enclave can read it, it was scrambled before it left the device, and the reply came from that enclave. Each is green because its checks passed.
3. In the panel, click each box under **Who can read your messages?**: your browser and the enclave show plaintext; NEAR AI's gateway shows the real request it got, which is ciphertext; **A standard AI API** shows the same message readable.
4. Press each **Try to break it** button. Every one is refused, and the panel names the check that caught it.
5. Click **New chat**, then **lab report** or **bank statement** under "No file handy?". A fictional PDF ([`web/samples/`](web/samples/)) is read in the page and attached with a question. Press send. No key is needed: the free demo allows up to 20 messages a day. The reply streams in and gets its own **Verified** badge.
6. Reload the page. The chat is in the sidebar, saved only in this browser, and is checked again when opened.

**Your own key:** paste a NEAR AI key ([cloud.near.ai](https://cloud.near.ai), $10 free credits at [nearbuilders.org/join](https://nearbuilders.org/join)) under **Key and model**. With a key, the page talks to NEAR AI directly and prompt20.com is off the path.

**Which models are private:** **Which models are private** in the sidebar asks NEAR AI for every model's attestation, live, with no key. On 2026-11-11, 12 of 63 models ran in their own TEE, 4 went through an attested router, and 47 (the Anthropic, OpenAI, Google and xAI models among them) were passed to outside providers. NEAR AI's API says so itself: "TEE attestation is not supported for external providers." Off Record only offers models with their own TEE.

## What the server keeps

No message content, in readable form or otherwise. The page is static files; saved chats are stored only in the browser (IndexedDB). What the server side does hold:

- **The free demo relay** ([`nginx/off-record-relay.js`](nginx/off-record-relay.js), locations in [`nginx/off-record.conf`](nginx/off-record.conf)) adds the demo key and passes the encrypted request on. It refuses any request whose messages are not E2EE ciphertext, any field the page does not send and any model outside the private list; it writes no access log, and passes on only the headers the call needs, so NEAR AI sees prompt20.com's address in place of the visitor's. Its daily counter is keyed by a keyed hash of IP and date, never the IP, and expires within two days. The rate limiter holds IPs in memory for about a minute. The connection to NEAR AI verifies NEAR AI's TLS certificate, so the demo key only goes to NEAR AI.
- **The evidence pass-through** (`/intel/*`, `/verify/gpu`) carries only public hardware evidence to Intel and NVIDIA, which send no CORS headers. These requests use the site's normal access log (IP, path, time).
- Cloudflare sits in front of prompt20.com and sees the visitor's IP, as for any Cloudflare site. It sees the same ciphertext.

## Who can read your messages

| Party | Sees | Why |
|---|---|---|
| Your browser | Plaintext | You type it. It is encrypted here, only after the enclave checks pass. |
| prompt20.com | Nothing, or ciphertext on the free demo | With your own key, the page sends your message and key only to NEAR AI. On the free demo, prompt20.com relays the same ciphertext the gateway sees and adds the demo key. It also relays public evidence: Intel's signed collateral and the GPU evidence for NVIDIA. The page loads no analytics. |
| NEAR AI's gateway | Ciphertext and metadata | Each message is encrypted to the enclave key. The gateway still sees the model, sizes, timing and your API key. |
| The enclave | Plaintext | Only the holder of the key named in the hardware quote, with this run's nonce, can decrypt. |

Click any party to see exactly what it sees, including the real request body the gateway received. A fifth box, **A standard AI API**, shows the same message in the usual request format with its sensitive items highlighted. One line sums it up: for the sample, **0 of 7 sensitive items readable in transit here, 7 of 7 with a standard AI API**. Metadata (model, sizes, timing, IP, API key) is visible either way. In our browser tests, no encrypted chat request contained any of the message's text.

## The send gate

Steps 1 to 4 must pass before anything is sent. Steps 5 and 6 check the reply. All six run again on any receipt:

1. **Enclave checked.** The model runs in its own TEE on NEAR AI (not an outside provider). dstack's event log replays to the quote's RTMR3, so the enclave app id and compose hash are measured, and it is not a debug enclave. The full Intel DCAP check runs in the page (see below): the quote's signature chain to Intel's root, and Intel's signed collateral for TCB status and revocation. NVIDIA's attestation tokens are verified in the page against NVIDIA's published keys: this nonce, debug off, secure boot on.
2. **Fresh challenge.** The quote and the GPU evidence both contain a random nonce made for this run.
3. **Key bound.** The quote's report data names the model's Ed25519 key.
4. **Encrypted to that key.** Every message is encrypted in the browser with [NEAR AI E2EE v2](https://docs.near.ai/cloud/guides/e2ee-chat-completions) (X25519, HKDF-SHA256, XChaCha20-Poly1305). Replies come back encrypted to a one-time key made in the page.
5. **Reply signed.** Every reply is signed by the attested key over `sha256(request):sha256(response)` of the exact encrypted bytes sent and received.
6. **Shown = signed.** The receipt keeps each message's one-time secret, so a checker opens every encrypted field and confirms it decrypts only with the key in the quote and says what the page shows.

## What code is running

Attestation usually stops at "an enclave app with this hash". The lab follows the chain down to the inference engine. Every link below is checked in the page and by `npm run verify`. The compose file is part of the **Verified** verdict; the deploy log, the public deploy file and the gateway are shown as their own results, and a failure there turns its own row red without changing the verdict:

1. **Compose file.** The enclave's `app_compose` hashes to the value in the quote's MRCONFIGID (`01 || sha256`) and to the compose-hash event replayed into RTMR3. It pins NEAR AI's `compose-manager` image by digest.
2. **Deploy log.** The compose manager starts the model containers at runtime and logs every action. The page hashes the log (canonical JSON, as NEAR AI's [inference-sdk](https://github.com/nearai/inference-sdk) does) and finds that hash with this run's nonce in a second TDX quote, from the same VM (same MRTD and RTMR0 to RTMR3). Intel's DCAP check runs on that quote too.
3. **Public deploy file.** The log names the file and git commit each container came from. The page fetches that file from [nearai/cvm-compose-files](https://github.com/nearai/cvm-compose-files) at that commit and checks it hashes to the sha256 in the signed log.
4. **Engine and weights.** From that file: the container serving the model, its engine image (pinned by digest, or built in the enclave from the file) and the model weights and revision it is labelled with. For the sample: `lmsysorg/sglang@sha256:febfb971c735...`, `Qwen/Qwen3.8-27B-FP8` at revision `017b9c7`.
5. **Gateway.** NEAR AI's gateway, which relays the ciphertext, runs in its own enclave. Its quote names its key and this run's nonce, its compose file matches (image `nearaidev/cloud-api@sha256:d74c3c3eb67c...`), and Intel's DCAP check passes on it.

On 2026-11-11 all five private chat models (Qwen3.8-27B, Qwen3.6-35B, Qwen3-VL-30B, GLM-5.3-Flash, DeepSeek-V4.1-Flash) linked up end to end.

## Chat receipts

A chat receipt holds the attestation (with this chat's nonce), the instructions, each message, and every call's exact request and response bytes with the one-time secrets that open them. Turn *i* is checked to have sent exactly the instructions, every earlier message and its signed reply, and message *i*, all encrypted to the attested key. A rewritten earlier message, a dropped turn or a flipped byte in a streamed reply is refused (`npm test` covers each). Streamed replies are signed too: NEAR AI's signature covers `sha256` of the whole event stream, which the page keeps byte for byte. Stopping a reply discards that turn, so a receipt never holds an unsigned answer.

## Try to break it

The page runs five attacks against the real checks. Each is refused, and the gate steps it breaks turn red:

| Attack | Refused by |
|---|---|
| Tamper with the reply: flip one byte of the encrypted reply | The encryption and the reply signature |
| Use a fake lock: swap in a key the quote does not contain | Key binding, encryption and signatures |
| Forge the proof: rewrite the quote so it names the attacker's key | Intel's signature, checked in the page (the key binding alone would pass) |
| Replay an old proof: offer the quote against a new challenge | The fresh nonce |
| Send to Claude (not private): a model NEAR AI runs at an outside provider | Stopped before sending: NEAR AI reports no TEE for it |

## Sensitive items, found inside the enclave

When you ask privately, a second encrypted, signed call asks the enclave model to list the sensitive items in your message (names, ages, health data, medications, IDs and so on). The page keeps only items that appear verbatim in the message, highlights them in every view, and counts them on the meter: for the sample, **0 of 7 readable here, 7 of 7 in a standard API** (a name, an age, four lab values, a medication).

We did not use NEAR AI's `/v1/privacy/classify` endpoint for this, though it runs `openai/privacy-filter` in a TEE: it does not accept E2EE (we sent an encrypted input and it scanned the ciphertext), so a live message would reach the gateway in plaintext.

## Cost, and paying it with NEAR staking

This is where NEAR fits beyond the enclaves: private inference runs on NEAR AI Cloud, and its credits can be paid by NEAR staking rewards. Each run shows its cost in NEAR AI credits, from the real token usage and NEAR AI's published model prices (the sample question cost $0.0024 for 2 calls). NEAR AI's [Staking for Inference](https://docs.near.ai/cloud/staking-for-inference/overview) lets NEAR staking rewards pay those credits while the stake stays yours. That is set up on NEAR AI's side; Off Record shows the cost and links to it, and runs no staking flow itself.

## Findings for the NEAR AI team

Things we hit while building, in case they help:

1. **The PII endpoint has no E2EE.** `/v1/privacy/classify` with `x-encryption-version: 2` treats the ciphertext as the input, so private apps cannot use it on sensitive text without the gateway reading it.
2. **47 of 63 models are external.** Only 12 run in their own TEE (on 2026-11-11). The attestation error says so, but `/v1/models` does not, so a client must probe each model to know.
3. **One key covers every instance of a model.** A signature identifies the deployment, not the machine that served the request.
4. **The verifiers block browsers.** Intel's PCS (collateral) and NVIDIA NRAS send no CORS headers, so a browser verifier needs a pass-through for them. NRAS also rejects any request carrying an `Origin` header. NVIDIA's JWKS is open, so the GPU token signatures can be checked in the browser.
5. **The staking farm configuration needs a NEAR login session.** `/v1/staking/farm/config` rejects API keys, so a tool cannot show a live staking quote without the user signing in.
6. **One VM serves many models, and only the deploy log says which container is which.** On 2026-11-11 the Qwen3.8-27B enclave's deploy log listed 48 running services, including several other models. Each model has its own key, but the hardware measurement covers the compose manager, so a verifier must check the deploy log (a second quote) to learn which engine serves a model. Documenting this next to the attestation API would help.

## Check the page itself

The checks run in code that prompt20.com serves, so the question is whether that code is this repository's. At any commit:

```sh
npm run check-live
```

It fetches every file under `web/` from https://prompt20.com/tools/off-record/ and compares SHA-256 hashes with the checkout, printing `MATCH` or `DIFFERS` per file. The page's Content-Security-Policy allows scripts only from prompt20.com, and every script it loads is in `web/`. Two shared site stylesheets (`/tools/tool.css`, `/tools/splash.css`) come from the prompt20 site and are outside this check. The demo relay runs on the server, so it cannot be hashed from outside; it only ever receives ciphertext, and a reply it changed would fail its signature.

## Run it locally

Node 20 or later.

```sh
npm install
npm test                # 25 offline tests, run in CI: the recorded run, the attacks, Intel collateral
npm run check-live      # the live page's files match this checkout, file by file
npm run verify          # the recorded two-turn chat, no key: asks Intel, NVIDIA and NEAR AI now
npm run tamper          # flip one byte in the reply first: prints NOT VERIFIED and exits 1
npm run swap-message    # rewrite the message in the receipt: NOT VERIFIED
npm start               # the page at http://localhost:8787/tools/off-record/ (NEARAI_KEY=sk-... npm start for keyless sends)
NEARAI_KEY=sk-... npm run capture   # record a new two-turn chat into web/sample-chat.json
```

`npm run verify` prints one PASS or FAIL line per check and ends with `VERIFIED`.

## How it is built

| File | What it does |
|---|---|
| [`web/engine.js`](web/engine.js) | Sends the message and runs every check. Plain ES module, shared by the page and the Node scripts, so the browser and the command line run the same code. |
| [`web/dcap.js`](web/dcap.js) | Intel DCAP in the page: the TDX quote's signature chain to Intel's pinned root, then TCB status, QE identity and revocation from Intel's signed collateral. |
| [`web/e2ee.js`](web/e2ee.js) | End-to-end encryption to the attested model key, and opening fields again when checking a receipt. |
| [`web/vendor/noble.js`](web/vendor/noble.js) | The audited [noble](https://paulmillr.com/noble/) curves, hashes and ciphers (MIT), bundled from `vendor-src/noble.js` with esbuild so the page loads no third-party script for its cryptography. |
| [`web/lab.js`](web/lab.js) | The page: chat, streaming, attachments, saved chats (IndexedDB), send gate, who-sees-what views, attacks, model scan. Every request has a deadline; reads retry, sends never do. |
| [`web/vendor/pdfjs`](web/vendor/pdfjs) | Mozilla's pdf.js 4.10.38 (Apache-2.0), loaded only when you attach a PDF, so PDFs are read in the page. |
| [`web/index.html`](web/index.html), [`web/style.css`](web/style.css) | The page, as served on prompt20.com. |
| [`web/sample.js`](web/sample.js), [`web/sample-chat.json`](web/sample-chat.json), [`web/sample-ask.json`](web/sample-ask.json) | A fictional patient's lab results; a real recorded two-turn chat about them (the demo), and an earlier one-question receipt kept to test that old receipts still verify. |
| [`scripts/verify-receipt.mjs`](scripts/verify-receipt.mjs) | Command-line receipt checker. |
| [`test/engine.test.mjs`](test/engine.test.mjs), [`test/fixtures`](test/fixtures) | Offline tests, run in CI on every push: the recorded run verifies; tampered replies, swapped keys, forged and replayed quotes, edited deploy logs and compose files, and edited or stale Intel collateral are refused. |
| [`scripts/serve.mjs`](scripts/serve.mjs) | Local server with the same verifier pass-through as production. Keyless sends need `NEARAI_KEY=sk-... npm start`; otherwise paste a key under Key and model. |
| [`nginx/off-record.conf`](nginx/off-record.conf) | The production pass-through: four fixed Intel PCS paths (GET only) and NVIDIA's verifier, rate limited. |

**Where your data goes.** With your own key, the browser calls `cloud-api.near.ai` directly (NEAR AI allows prompt20.com cross-origin), so prompt20.com never receives your key or your prompt. On the free demo, the same encrypted request goes through prompt20.com's relay, which adds the demo key. Either way every message is encrypted before it leaves the page. Open the browser's network tab during a run: the chat request bodies are hex ciphertext. In our test, none of the 9 request bodies contained any of the prompt's text. The page's Content-Security-Policy limits connections to NEAR AI, NVIDIA, GitHub's raw files (for NEAR AI's public deploy files) and prompt20's own pages and data API, so a reviewer can confirm this in the page source. Intel's PCS and NVIDIA's verifier send no CORS headers, so only public evidence goes through a pass-through on prompt20.com: Intel's collateral (fetched by FMSPC, no quote sent) and the GPU evidence, neither of which contains a prompt.

**Where the checks run.** The page reads `report_data` (bytes 568 to 632) and RTMR3 (bytes 520 to 568) out of the quote itself, and replays the event log with SHA-384. The quote's Intel signature chain is checked in the page by [`web/dcap.js`](web/dcap.js), with no Intel verifier service: the attestation key's ECDSA P-256 signature over the quote, the quoting enclave's report binding that key (`sha256(key || auth data)`), the PCK certificate's signature on that report, the PCK chain to Intel's SGX Root CA (its key pinned in the code), certificate validity, and Intel's TDX quoting-enclave signer. Then the page finishes the DCAP check itself with Intel's signed collateral, fetched for the platform's FMSPC (read from the PCK certificate's SGX extension): the TCB info and the TD quoting-enclave identity, each signed by Intel's TCB Signing key and chained to the same pinned root, and the PCK and root CRLs, signed by Intel. From these it computes the platform's TCB level (CPU SVN components and PCE SVN from the PCK certificate, TDX components from the quote's TEE_TCB_SVN), the TDX module's level and signer, and the quoting enclave's level, and confirms neither the PCK certificate nor its CA is revoked. Collateral past its next-update date is refused. The same check runs on the deploy-log and gateway quotes. Because every piece is signed by Intel, the pass-through cannot change a verdict; it can only make a check fail as unreachable. The GPU evidence goes to NVIDIA's NRAS, and NVIDIA's tokens are verified in the page against NVIDIA's published keys (ES384). A receipt carries no vendor verdicts: every check, in the page or on the command line, asks Intel and NVIDIA again, and asks NEAR AI which enclave app serves the model today. `npm run verify` calls Intel and NVIDIA directly.

## Trust boundaries

- NEAR AI's gateway sees metadata: your IP, timing, message sizes, the model, request settings and your API key. On the free demo it sees prompt20.com's address and the demo key, and prompt20.com sees your IP.
- You trust the code this page delivers and NEAR AI's key management. Attestation shows what hardware and enclave app ran, not that the app never logs.
- Instances of one model share a key, so it identifies a deployment, not one machine.
- A receipt contains the one-time secrets that open its messages, so it reveals the chat to whoever holds it. Saved chats sit in this browser's storage unencrypted, like any web chat's local history; anyone with access to this browser profile can read them. Delete them in the chat list.
- A chat is attested once, when it starts. Each later reply must be signed by the same key, so a swapped enclave cannot answer, but the hardware proof itself is from the chat's start.
- The model weights are named by a label in NEAR AI's deploy file. The engine image is pinned, but the weights themselves are not measured.
- The app id is checked against the app NEAR AI serves today, through NEAR AI's own attestation endpoint. Judging that app's compose file (what code it runs) is NEAR AI's published deployment; the page shows the compose hash so you can compare it in NEAR AI's Verification Center.
- The CPU quote and the GPU evidence are tied together by the shared nonce, as in NEAR AI's own verifier. Neither vendor attests that link directly.
- NVIDIA's per-GPU tokens are checked against the overall result: each one's sha256 must match its digest in `submods`, and each must carry the run's nonce.
- Intel TCB statuses `SWHardeningNeeded` and `ConfigurationNeeded` are accepted, and their advisory IDs are shown in the proof panel. The page cannot confirm the platform applied those mitigations.
- The page does not pin an approved app or compose hash of its own. It checks that the enclave app is the one NEAR AI serves for the model today, so a deployment NEAR AI itself changed would still pass.

## NEAR HACKATHON

Built for the Privacy & Private AI track. My other, independent entry is [NEARnest](https://github.com/edwardtay/nearnest), a yield agent on NEAR mainnet whose key is held to an on-chain policy. The two share no code.

Written with help from AI coding assistants (Claude Code and Codex). I reviewed and tested all of it.

## License

MIT
