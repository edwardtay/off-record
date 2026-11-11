# Private Prompt Lab

Optimise a proprietary system prompt inside a hardware enclave on NEAR AI Cloud, run your own test cases on both versions, and check the proof yourself.

**Live:** https://prompt20.com/tools/private-prompt/

A company's system prompt is product IP. Pasting it into an ordinary prompt optimiser hands it to that service. Private Prompt Lab sends it from your browser straight to a model running in a TEE on NEAR AI Cloud (Intel TDX with NVIDIA confidential GPUs), and the page checks every piece of evidence before showing a result:

1. The model's Intel TDX quote contains a fresh random nonce made for this run and the model's own signing key. The NVIDIA GPU evidence carries the same nonce.
2. dstack's event log replays to the quote's RTMR3, so the enclave app id and compose hash are measured values, and the enclave is not in debug mode.
3. Intel's DCAP chain accepts the quote, and NVIDIA's attestation service accepts the GPUs, returning a signed token with this nonce, debug off and secure boot on.
4. Only after those pass does the browser send the prompt. Every reply (the optimiser call and each test case on both prompts) is signed by the attested key over `sha256(request):sha256(response)` of the exact bytes the browser sent and received.
5. The optimised prompt and the list of cuts are read from the signed reply, and each test ran exactly once per prompt with the message shown.

Then it shows input tokens per call before and after, the monthly saving at your production model's price (live from data.prompt20.com), a word diff, the cuts the model made, the rules it kept, and pass or fail for each test case on both prompts.

On the sample (a fictional support-agent prompt), it took 580 tokens per call to 306 (47% fewer) with 4 of 4 tests still passing, and all 9 replies verified.

## Try it

**No key needed:** open https://prompt20.com/tools/private-prompt/, choose **Check a run**, press **Check the recorded sample run**. You see VERIFIED, the token saving, the diff, the tests and every proof row. Press **Flip one byte in a reply**: the verdict turns NOT VERIFIED.

**Your own prompt:** get a NEAR AI key at https://cloud.near.ai ($10 free credits at https://nearbuilders.org/join), paste it on the **Optimise a prompt** tab with your system prompt and test cases, and press **Optimise in the enclave**. A run takes about 30 seconds and costs a few cents. **Download the receipt** saves the evidence so anyone can check it later.

**Which models are private:** the **Private models** tab asks NEAR AI for every model's attestation, live, with no key. On 2026-11-11, 12 of 63 models ran in their own TEE, 4 went through an attested router, and 47 (the Anthropic, OpenAI, Google and xAI models among them) were passed to outside providers. NEAR AI's API says so itself: "TEE attestation is not supported for external providers." The lab only lets you pick a model with its own TEE.

## Run it locally

Node 20 or later.

```sh
npm install
npm run verify          # check the recorded sample receipt, no key: asks Intel, NVIDIA and NEAR AI now
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
| [`web/lab.js`](web/lab.js) | The page: tabs, test-case editor, model scan, diff, results. |
| [`web/index.html`](web/index.html), [`web/style.css`](web/style.css) | The page, as served on prompt20.com. |
| [`web/sample.js`](web/sample.js), [`web/sample-run.json`](web/sample-run.json) | The fictional Northwind Pay prompt with 4 test cases, and a real recorded run of it. |
| [`scripts/verify-receipt.mjs`](scripts/verify-receipt.mjs) | Command-line receipt checker. |
| [`scripts/serve.mjs`](scripts/serve.mjs) | Local server with the same verifier pass-through as production. |
| [`nginx/private-prompt.conf`](nginx/private-prompt.conf) | The production pass-through for the two vendor verifiers. |

**Where your data goes.** The browser calls `cloud-api.near.ai` directly (NEAR AI allows prompt20.com cross-origin), so prompt20.com never receives your key or your prompt. The page's Content-Security-Policy limits connections to NEAR AI, prompt20's own pages and data API, and page-view analytics, so a reviewer can confirm this in the page source. Intel's and NVIDIA's verifiers send no CORS headers, so only the public attestation evidence (the TDX quote and the GPU evidence, which contain no prompt) goes through a pass-through on prompt20.com.

**Where the checks run.** The page reads `report_data` (bytes 568 to 632) and RTMR3 (bytes 520 to 568) out of the quote itself, and replays the event log with SHA-384. The quote's Intel certificate chain is checked by Phala's public DCAP verifier, and the GPU evidence by NVIDIA's NRAS. A receipt carries no vendor verdicts: every check, in the page or on the command line, asks Intel and NVIDIA again, and asks NEAR AI which enclave app serves the model today.

## What it does not prove

- The app id is checked against the app NEAR AI serves today, through NEAR AI's own attestation endpoint. Judging that app's compose file (what code it runs) is NEAR AI's published deployment; the page shows the compose hash so you can compare it in NEAR AI's Verification Center.
- The CPU quote and the GPU evidence are tied together by the shared nonce, as in NEAR AI's own verifier. Neither vendor attests that link directly.
- The must and must-not rules for each test are yours and are not signed. Pass or fail is recomputed from the signed replies on every check.
- The optimised prompt passing your test cases means it behaves the same on those cases, not on every input. Write test cases for the rules that matter.
- Token counts come from the enclave model's tokenizer (Qwen). Your production model counts a few percent differently.
- Attestation shows what code and hardware served the request. It does not show what NEAR AI's gateway logs, which NEAR AI documents separately.

## NEAR HACKATHON

Built for the Privacy & Private AI track. My other, independent entry is [NEARnest](https://github.com/edwardtay/nearnest), a yield agent on NEAR mainnet whose key is held to an on-chain policy. The two share no code.

Written with help from AI coding assistants (Claude Code and Codex). I reviewed and tested all of it.

## License

MIT
