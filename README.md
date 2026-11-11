# Private Prompt Lab

Verifiable private AI in the browser. Before your prompt leaves, the page checks the enclave on NEAR AI Cloud, then encrypts the prompt to the key inside its hardware quote and verifies the signed, encrypted reply. You can see the ciphertext NEAR AI's gateway received, and try to break the proof yourself.

**Live:** https://prompt20.com/tools/private-prompt/

## Who can read your prompt

| Party | Sees | Why |
|---|---|---|
| Your browser | Plaintext | You type it. It is encrypted here, only after the enclave checks pass. |
| prompt20.com | Nothing | The page calls NEAR AI directly. Its Content-Security-Policy blocks every other destination, including analytics. |
| NEAR AI's gateway | Ciphertext and metadata | Each message is encrypted to the enclave key. The gateway still sees the model, sizes, timing and your API key. |
| The enclave | Plaintext | Only the holder of the key named in the hardware quote, with this run's nonce, can decrypt. |

The page shows what you wrote beside the exact request body the gateway received. In our browser tests, none of 16 encrypted chat requests contained any of the prompt's text.

## The send gate

Nothing is sent until these pass, and every check runs again on any receipt:

1. **Enclave checked.** The model runs in its own TEE on NEAR AI (not an outside provider). dstack's event log replays to the quote's RTMR3, so the enclave app id and compose hash are measured, and it is not a debug enclave. Intel's DCAP chain accepts the TDX quote. NVIDIA's attestation tokens are verified in the page against NVIDIA's published keys: this nonce, debug off, secure boot on.
2. **Fresh challenge.** The quote and the GPU evidence both contain a random nonce made for this run.
3. **Key bound.** The quote's report data names the model's Ed25519 key.
4. **Encrypted to that key.** Every message is encrypted in the browser with [NEAR AI E2EE v2](https://docs.near.ai/cloud/guides/e2ee-chat-completions) (X25519, HKDF-SHA256, XChaCha20-Poly1305). Replies come back encrypted to a one-time key made in the page.
5. **Reply signed.** Every reply is signed by the attested key over `sha256(request):sha256(response)` of the exact encrypted bytes sent and received.
6. **Shown = signed.** The receipt keeps each message's one-time secret, so a checker opens every encrypted field and confirms it decrypts only with the key in the quote and says what the page shows.

## Try to break it

The page runs four attacks against the real checks, and each is refused:

| Attack | Refused by |
|---|---|
| Flip one byte of an encrypted reply | The encryption and the reply signature |
| Swap in a key the quote does not contain | Key binding, encryption and signatures |
| Replay the quote against a new challenge | The fresh nonce |
| Send to a model NEAR AI runs at an outside provider (Claude, GPT, Gemini on NEAR AI) | Stopped before sending: NEAR AI reports no TEE for it |

## Two things to do with it

**Ask privately.** Send any sensitive message. The recorded sample is a fictional patient's lab results.

**Optimise a prompt privately.** A company's system prompt is product IP. The lab shortens it in the enclave and runs your test cases on both versions, all encrypted. It gives two separate verdicts: **VERIFIED** (the proof holds) and **Safe to adopt** (no test the original passes fails on the new prompt). Two recorded runs of a fictional support-agent prompt with 7 tests:

| Run | Tokens per call | Tests | Verdicts |
|---|---|---|---|
| Careful (keep every rule) | 580 to 311, 46% fewer | 7 of 7 | VERIFIED, safe to adopt |
| Extreme (40-word budget) | 580 to 129, 78% fewer | 3 of 7 | VERIFIED, 4 regressions caught: the sign-off dropped twice, "contact the merchant" lost from late refunds, and a fraud report no longer escalates |

## Try it

**No key needed:** open https://prompt20.com/tools/private-prompt/. It checks the recorded private question as it loads: all six gate steps green, the plaintext beside the ciphertext, VERIFIED. Press the four **Try to break it** buttons. Under **Check a run**, open the two prompt-edit runs.

**Your own prompt:** get a NEAR AI key at https://cloud.near.ai ($10 free credits at https://nearbuilders.org/join), open **Run privately**, paste the key (kept in the page only, never stored) and send. Watch the gate: "No prompt sent yet" until the enclave checks pass.

**Which models are private:** the **Models** tab asks NEAR AI for every model's attestation, live, with no key. On 2026-11-11, 12 of 63 models ran in their own TEE, 4 went through an attested router, and 47 (the Anthropic, OpenAI, Google and xAI models among them) were passed to outside providers. NEAR AI's API says so itself: "TEE attestation is not supported for external providers." The lab only offers models with their own TEE.

## Run it locally

Node 20 or later.

```sh
npm install
npm run verify:ask      # the private question: VERIFIED, and the decrypted reply
npm run verify          # the careful prompt edit, no key: asks Intel, NVIDIA and NEAR AI now
npm run verify:extreme  # the 40-word run: VERIFIED, and NOT SAFE with 4 regressions
npm run tamper          # flip one byte in a reply first: prints NOT VERIFIED and exits 1
npm run swap-test       # rewrite a test message in the receipt: NOT VERIFIED
npm start               # the page at http://localhost:8787/tools/private-prompt/
NEARAI_KEY=sk-... npm run capture   # record a new sample run into web/sample-run.json
```

`npm run verify` prints one PASS or FAIL line per check and ends with `VERIFIED`.

## How it is built

| File | What it does |
|---|---|
| [`web/engine.js`](web/engine.js) | Runs the lab and every check. Plain ES module with no imports, shared by the page and the Node scripts, so the browser and the command line run the same code. |
| [`web/e2ee.js`](web/e2ee.js) | End-to-end encryption to the attested model key, and opening fields again when checking a receipt. |
| [`web/vendor/noble.js`](web/vendor/noble.js) | The audited [noble](https://paulmillr.com/noble/) curves, hashes and ciphers (MIT), bundled from `vendor-src/noble.js` with esbuild so the page loads no third-party script for its cryptography. |
| [`web/lab.js`](web/lab.js) | The page: tabs, test-case editor, model scan, diff, results. |
| [`web/index.html`](web/index.html), [`web/style.css`](web/style.css) | The page, as served on prompt20.com. |
| [`web/sample.js`](web/sample.js), [`web/sample-ask.json`](web/sample-ask.json), [`web/sample-run.json`](web/sample-run.json), [`web/sample-extreme.json`](web/sample-extreme.json) | Fictional samples: a patient's lab results, and the Northwind Pay prompt with 7 test cases. Real recorded runs: the private question, a careful edit and a 40-word edit. |
| [`scripts/verify-receipt.mjs`](scripts/verify-receipt.mjs) | Command-line receipt checker. |
| [`scripts/serve.mjs`](scripts/serve.mjs) | Local server with the same verifier pass-through as production. |
| [`nginx/private-prompt.conf`](nginx/private-prompt.conf) | The production pass-through for the two vendor verifiers. |

**Where your data goes.** The browser calls `cloud-api.near.ai` directly (NEAR AI allows prompt20.com cross-origin), so prompt20.com never receives your key or your prompt, and every message is encrypted before it leaves the page. Open the browser's network tab during a run: the chat request bodies are hex ciphertext. In our test, none of the 9 request bodies contained any of the prompt's text. The page's Content-Security-Policy limits connections to NEAR AI, prompt20's own pages and data API, and page-view analytics, so a reviewer can confirm this in the page source. Intel's and NVIDIA's verifiers send no CORS headers, so only the public attestation evidence (the TDX quote and the GPU evidence, which contain no prompt) goes through a pass-through on prompt20.com.

**Where the checks run.** The page reads `report_data` (bytes 568 to 632) and RTMR3 (bytes 520 to 568) out of the quote itself, and replays the event log with SHA-384. The quote's Intel certificate chain is checked by Phala's public DCAP verifier, and the GPU evidence by NVIDIA's NRAS. A receipt carries no vendor verdicts: every check, in the page or on the command line, asks Intel and NVIDIA again, and asks NEAR AI which enclave app serves the model today. NVIDIA's tokens are verified in the page against NVIDIA's published keys (ES384), so the GPU verdict does not depend on trusting prompt20.com's pass-through. The Intel verdict does: it comes from Phala's DCAP verifier through that pass-through. To remove that trust, run `npm run verify`, which calls Phala directly, or check the quote with Intel's own `dcap-qvl`.

## Trust boundaries

- NEAR AI's gateway sees metadata: your IP, timing, message sizes, the model, request settings and your API key.
- You trust the code this page delivers and NEAR AI's key management. Attestation shows what hardware and enclave app ran, not that the app never logs.
- Instances of one model share a key, so it identifies a deployment, not one machine.
- A receipt contains the one-time secrets that open its messages, so it reveals the prompt to whoever holds it. Share a receipt only when you mean to share the prompt.
- The app id is checked against the app NEAR AI serves today, through NEAR AI's own attestation endpoint. Judging that app's compose file (what code it runs) is NEAR AI's published deployment; the page shows the compose hash so you can compare it in NEAR AI's Verification Center.
- The CPU quote and the GPU evidence are tied together by the shared nonce, as in NEAR AI's own verifier. Neither vendor attests that link directly.
- The must and must-not rules for each test are yours and are not signed. Pass or fail is recomputed from the signed replies on every check.
- The optimised prompt passing your test cases means it behaves the same on those cases, not on every input. Write test cases for the rules that matter.
- Token counts come from the enclave model's tokenizer (Qwen). Your production model counts a few percent differently.

## NEAR HACKATHON

Built for the Privacy & Private AI track. My other, independent entry is [NEARnest](https://github.com/edwardtay/nearnest), a yield agent on NEAR mainnet whose key is held to an on-chain policy. The two share no code.

Written with help from AI coding assistants (Claude Code and Codex). I reviewed and tested all of it.

## License

MIT
