# BaitWatch

A Chrome extension that catches scam and phishing messages while you read them,
and explains in plain language what the sender is actually trying to get.

Originally built for a hackathon by **Sreekar**.

**Version 2 has no backend.** Detection runs entirely inside the browser. There
is no server to deploy, nothing to pay for, and no message leaves your computer
unless you explicitly turn on the optional Claude second opinion with your own
API key.

```
┌─ your browser ─────────────────────────────────────────────┐
│                                                            │
│  content script          service worker                    │
│  ┌──────────────┐        ┌──────────────────────────────┐  │
│  │ site adapter │──text─▶│  1. heuristics  (16 rules)   │  │
│  │  Gmail       │        │  2. URL analysis             │  │
│  │  WhatsApp    │◀verdict│  3. on-device classifier     │  │
│  │  Telegram    │        └──────────────┬───────────────┘  │
│  │  generic     │                       │ only if uncertain│
│  └──────────────┘                       ▼                  │
└─────────────────────────────────────────┼──────────────────┘
                                          │ your API key
                                   Claude (optional, off by default)
```

## What it does

- **Scans as you read.** Open an email or chat and it is checked in place — no
  copy-pasting. Dedicated adapters for Gmail, WhatsApp Web, and Telegram Web;
  a conservative generic scanner everywhere else.
- **Explains itself.** Every warning says *why*: "it asks for payment in gift
  cards", "this domain is one character away from PayPal's real one". A score
  with no reason is useless to the person who has to make the decision.
- **Runs on your device.** The classifier ships inside the extension. No
  network call, no account, works offline.
- **Optional second opinion.** For genuinely ambiguous messages you can let
  Claude weigh in using your own Anthropic API key. Off by default.
- **Scan a whole page on demand.** A **Scan this entire page** button judges
  everything at once: the visible text, every link's actual destination, form
  targets, and the site's own address. This is the one to use on a page that
  asks you to sign in — a credential-harvest page reads "Sign in to continue"
  and hides the hostile domain in the link, so scanning text alone misses the
  only signal that matters.
- **Right-click anything.** Select text on any page → *Check this text for
  scams*. This is the escape hatch for canvas-rendered apps and PDFs.
- **Remembers your decisions.** Block a sender and it stays blocked; mark one
  safe and it stops being flagged. History exports to CSV.

## How detection works

Three layers, deliberately **not** averaged together.

**1. Heuristics** — 16 rules for the social-engineering tactics that stay
constant across rewrites and languages: OTP and password requests, gift-card
payment, UPI collect-requests, crypto transfers, invoice redirection, boss
impersonation, arrest threats, secrecy demands, remote-access installs.

There are also three *exonerating* rules that push ordinary mail back down.
Without them, any email containing "urgent" gets flagged, and an extension that
cries wolf is one that gets uninstalled. An exonerating rule cannot rescue a
message that triggered something severe — "as discussed, send me your OTP"
gets no discount.

**2. URL analysis** — lookalike domains via edit distance plus homoglyph and
leetspeak folding (`paypa1.com`, `рaypal.com`, `paypal-secure.com`,
`amazon.com.delivery.tk`), link shorteners, high-abuse TLDs, raw-IP hosts,
punycode, and the `https://apple.com@evil.tk` username trick.

Domain boundaries come from the full Mozilla Public Suffix List, which matters
more than it sounds. Its private section covers hosting platforms, so
`evil.github.io` and `legit.github.io` are correctly treated as two separate
domains. Free hosting is where a large share of phishing pages actually live,
and any shorter list collapses every page on a platform — hostile and
legitimate alike — into one.

**3. On-device classifier** — the TF-IDF + logistic regression model from V1,
exported to JSON and re-implemented in ~40 lines of JavaScript. No WebAssembly
(Manifest V3's CSP makes that a fight), no multi-megabyte runtime, no fetch:
90 KB of weights shipped in the package.

The rule layers can convict on their own — a gift-card request is a scam
regardless of what a bag-of-words model thinks. The classifier only nudges
borderline cases, contributing at most ~22 of the 100 points. Averaging the
three would let a confident-but-wrong model bury the signal the user needed.

## Install

```bash
git clone https://github.com/sreekarseera/baitwatch
cd baitwatch
```

Then in Chrome: `chrome://extensions` → enable **Developer mode** → **Load
unpacked** → select the `extension/` folder.

That's the whole setup. No build step, no `npm install`, no server. The
extension is committed ready to run, model weights included.

### Optional: the Claude second opinion

Click the extension → ⚙ → paste an [Anthropic API key](https://console.anthropic.com)
→ **Test**. It is used only for messages the on-device layers can't settle
(roughly one in five), and the key is stored in `chrome.storage.local` on your
machine.

## Retraining the model

Only needed if you change the dataset. Requires `scikit-learn`, `pandas`,
`joblib`.

```bash
cd training
pip install -r requirements.txt
python3 train_model.py     # trains, prints metrics, writes model.joblib
python3 export_model.py    # writes extension/engine/model-weights.json
cd .. && python3 tests/test_parity.py   # REQUIRED — see below
```

**Always run the parity test after retraining.** `extension/lib/text.js`
re-implements scikit-learn's tokenizer by hand. If the two ever drift apart the
extension keeps producing confident, wrong answers with nothing at runtime to
catch it. The test runs the whole dataset plus adversarial unicode through both
implementations and fails on any disagreement.

Current model: 96.4% validation accuracy, 1,970 terms, 90 KB.

## Tests

```bash
python3 tests/run_all.py                 # all three layers
python3 tests/run_all.py --no-browser    # skip Chrome
```

See [`tests/README.md`](tests/README.md) — including the caveat that **branded
Google Chrome 137+ silently refuses to load unpacked extensions from the command
line**, so the browser layer needs Chrome for Testing.

## Layout

```
extension/
  engine/      heuristics, URL analysis, model inference, Claude tier
  content/     site adapters, DOM scanner, in-page warning UI
  background/  service worker — the only place analysis runs
  popup/       manual check, history, sender lists
  options/     settings, API key, model info
  lib/         storage, text utilities, CSV export
training/      dataset, trainer, JSON exporter, icon generator
tools/         build script for the public suffix list
tests/         parity, engine, browser smoke
```

## License

BaitWatch is MIT licensed — see [`LICENSE`](LICENSE).

`extension/engine/psl-data.js` is generated from the [Mozilla Public Suffix
List](https://publicsuffix.org/), which is licensed under MPL-2.0. That license
covers the data file alone and does not extend to the rest of the project.
Regenerate it with `python3 tools/build_psl.py`.

## Known limits

- **Canvas-rendered apps** (Google Docs, Figma) draw text to a canvas rather
  than the DOM, so nothing can read it. Use right-click → *Check this text for
  scams* on a selection instead.
- **Chrome-internal pages** (`chrome://`, the Web Store) block all extensions
  by design.
- **The dataset is small and partly template-generated** — 281 rows. Five-fold
  cross-validation is 93% ±18%, and that variance is real. This is why the
  heuristic and URL layers, not the classifier, are what the verdict mostly
  rests on. Broadening the dataset with real-world scam corpora is the single
  highest-value improvement available.
- **Adapters are selector-based.** Gmail and WhatsApp change their DOM without
  notice; if auto-scan goes quiet on a site, the selectors in
  `extension/content/adapters.js` are the first place to look.

## What changed from V1

| | V1 | V2 |
|---|---|---|
| Backend | FastAPI on localhost:8000 | none — all in-browser |
| Detection | one model | heuristics + URL analysis + model, fused |
| Input | manual paste | auto-scan with per-site adapters, plus paste and right-click |
| Output | label + confidence | verdict, score, and reasons in plain language |
| Warning | banner for blocked emails | in-page card with reasons and actions, shadow-DOM isolated |
| Sender lists | blocklist | blocklist + allowlist |
| Tests | 17 e2e checks against the backend | 61 engine checks, model parity, 15 browser checks |
