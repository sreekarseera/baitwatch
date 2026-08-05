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
│  │ site adapter │──text─▶│  1. heuristics  (21 rules)   │  │
│  │  Gmail       │        │  2. URL analysis             │  │
│  │  WhatsApp    │◀verdict│  3. brand impersonation      │  │
│  │  Telegram    │        │  4. on-device classifier     │  │
│  │  generic     │        └──────────────┬───────────────┘  │
│  └──────────────┘                       │ only if uncertain│
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

Four layers, deliberately **not** averaged together.

**1. Heuristics** — 21 rules for the social-engineering tactics that stay
constant across rewrites and languages: OTP and password requests, gift-card
payment, UPI collect-requests, crypto transfers, invoice redirection, boss
impersonation, arrest threats, secrecy demands, remote-access installs,
family-emergency impersonation, failed-delivery fees, advance-fee job offers,
refund-callback traps, and 419-style windfall letters.

The last five came from the benchmark rather than from imagination: they were
the tactics it showed being missed, all scoring 23-33 against a threshold of
35. Adding them took the targeted miss rate from 15.7% to 3.6%.

Each is conjunctive, and the near-misses are the reason. "Hi mum, this is my
new number" is a real message people really send; so is "bro, send me the
wedding photos". Only a claimed relationship *and* a request for money *and*
either an unverifiable number or a sudden crisis is the tactic.

There are also three *exonerating* rules that push ordinary mail back down.
Without them, any email containing "urgent" gets flagged, and an extension that
cries wolf is one that gets uninstalled. An exonerating rule cannot rescue a
message that triggered something severe — "as discussed, send me your OTP"
gets no discount.

**2. URL analysis** — lookalike domains via edit distance plus homoglyph and
leetspeak folding (`paypa1.com`, `arnazon.com`, `paypal-secure.com`,
`amazon.com.delivery.tk`), link shorteners, high-abuse TLDs, raw-IP hosts,
and the `https://apple.com@evil.tk` username trick.

Non-Latin lookalikes are decoded before folding. A Cyrillic `рaypal.com`
reaches an extension as `xn--aypal-uye.com`, because that is what `new URL()`
returns — so folding runs on an ASCII envelope and finds nothing. With RFC 3492
decoding in front of it (`lib/punycode.js`), the Cyrillic `р` folds onto Latin
`p` like any other homoglyph and the warning can name the brand instead of
muttering about character sets.

Punycode on its own is not the signal, though. A domain written wholly in
Cyrillic, Han, or Devanagari is just a domain in that language; treating all of
them as suspicious flagged every legitimate German, Russian, Chinese and Indian
address. What actually indicates an attack is a *single label mixing
alphabets* — `рaypal` is one Cyrillic letter wearing five Latin ones. Checked
per label, since `香港.com` pairing Han with a Latin TLD is completely ordinary.

Domain boundaries come from the full Mozilla Public Suffix List, which matters
more than it sounds. Its private section covers hosting platforms, so
`evil.github.io` and `legit.github.io` are correctly treated as two separate
domains. Free hosting is where a large share of phishing pages actually live,
and any shorter list collapses every page on a platform — hostile and
legitimate alike — into one.

**3. Brand impersonation** — the URL layer asks whether the *domain* imitates a
brand. This asks the other half: does the page claim to *be* one? A credential
harvest usually doesn't bother with a clever domain. It sits on
`secure-portal-9f2.xyz`, puts a bank's name in the title, and shows a password
box. Nothing about that domain is suspicious in isolation; the mismatch between
what the page says it is and where it is served from is the entire signal.

The rule is conjunctive on purpose, because the failure mode here is warning
about ordinary browsing. A brand name in a title proves nothing — news and
review sites print them all day. So the page must *present itself* as the brand
(name in the title, or wired directly to its sign-in prompt), be served from a
domain the brand doesn't own, be thin enough to be a login page rather than an
article, and ask for a password or one-time code. "Sign in with Google" on a
site that isn't Google is explicitly not a claim to be Google.

**4. On-device classifier** — a TF-IDF + logistic regression model, exported to
JSON and re-implemented in ~40 lines of JavaScript. No WebAssembly (Manifest
V3's CSP makes that a fight), no multi-megabyte runtime, no fetch: 262 KB of
weights shipped in the package.

It is trained on 3,192 messages — 280 curated rows plus the SpamAssassin public
corpus, rebuilt by `training/build_corpus.py`. The corpus matters more than the
row count suggests. Its `hard_ham` folder is mail that *looks* like spam —
newsletters, offers, marketing from real senders — which is the most useful
thing available to a tool whose failure mode is crying wolf. It also removed a
confound: the curated legitimate rows averaged 61 characters against 100 for
the scams, so length alone carried signal that nothing in deployment would
reproduce.

Dropping every term appearing in fewer than three messages *raised* accuracy
from 94.99% to 96.09% while cutting the vocabulary from 151k terms to 24k — a
bigram seen once is memorised, not learned. Capping at 6,000 features then
lands on the size knee: 262 KB, within 0.12pp of a 929 KB model.

The rule layers can convict on their own — a gift-card request is a scam
regardless of what a bag-of-words model thinks. The classifier moves a verdict
by at most 50 of the 100 points in a message, and 22 on a whole-page scan,
where it is being asked about text unlike anything it was trained on. Both
ceilings sit below the score that convicts, so the model can raise a flag by
itself but never a red card by itself. Averaging the layers instead would let a
confident-but-wrong model bury the signal the user needed.

That ceiling was 22 everywhere while the model was 281 rows at 93% ±18%. The
effect was not caution but a dead end: 22 is below the threshold to warn at
all, so a message tripping no rule could never be flagged however certain the
model was — and short pretext-only phishing ("We detected unusual activity in
your bank account. Login to confirm.") has no link and no credential verb to
trip one. It scored 14 and passed as safe. On held-out data, lifting the
message ceiling to 50 cut misses from 72.8% to 33.2% with no movement in the
false positive rate.

Rules also read their context. "Enter your password" is a credential request in
a message and the most ordinary sentence in the world on the login page it
describes, so on a page carrying a real login form only asking you to *hand the
secret over* — "send me your OTP" — counts. Without that distinction the scan
flagged genuine bank and workplace logins as dangerous, which is precisely the
page it was built to be used on.

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

Current model: 95.9% validation accuracy, 95.5% ±1.2% five-fold CV,
6,000 terms, 262 KB.

## Tests

```bash
python3 tests/run_all.py                 # engine, model parity, benchmark, browser
python3 tests/run_all.py --no-browser    # skip Chrome
node tests/test_benchmark.mjs --verbose  # what it gets wrong, and how badly
```

`test_engine.mjs` asks whether specific cases behave correctly.
`test_benchmark.mjs` asks how often the extension is wrong, across the whole
corpus, through the real fused engine rather than the classifier alone — and
fails the build if the rates regress. Currently **0.55% of legitimate mail is
flagged**, 0.25% of it as dangerous, and 3.6% of targeted scams are missed.

Those gates are what make "reduce false positives" an actionable goal rather
than a feeling. Note that the corpus rows are also training rows, so the
benchmark flatters the model layer; the honest accuracy number is the
cross-validated one `train_model.py` prints.

See [`tests/README.md`](tests/README.md) — including the caveat that **branded
Google Chrome 137+ silently refuses to load unpacked extensions from the command
line**, so the browser layer needs Chrome for Testing.

## Layout

```
extension/
  engine/      heuristics, URL analysis, impersonation, model inference, Claude tier
  content/     site adapters, DOM scanner, in-page warning UI
  background/  service worker — the only place analysis runs
  popup/       manual check, history, sender lists
  options/     settings, API key, model info
  lib/         storage, text utilities, punycode, CSV export
training/      corpus builder, dataset, trainer, JSON exporter, icons
tools/         build script for the public suffix list
tests/         parity, engine, accuracy benchmark, browser smoke
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
- **The corpus is old, and American.** The 2,912 real messages come from the
  SpamAssassin public corpus, which is 2002-2003 mail. Its spam is mostly
  commercial advertising rather than credential phishing, and it has never seen
  a UPI collect-request. The 280 curated rows carry the India-specific tactics,
  and they are the ones the benchmark grades.
- **The last few misses are one-offs.** 3.6% of targeted scams still get
  through, and unlike the clusters that produced the five newest rules these
  no longer share a shape — a payroll-redirect, a pre-approved-loan fee, a
  traffic-fine "settlement". Each would need its own rule for one row of
  benefit, which is how a rule set starts overfitting its own test set.
- **Every rule is English-only.** The heuristics encode UPI collect-requests
  and digital-arrest threats, which are India-specific tactics, but match only
  English wording. A Hinglish or Devanagari version of the same scam trips
  nothing. This is the largest remaining gap.
- **Homoglyph folding is a hand-picked table, not the full confusables set.**
  The Cyrillic and Greek letters with exact Latin twins are covered, which is
  where the abuse concentrates, but Unicode defines thousands more. Importing
  Unicode's own `confusables.txt` would make this exhaustive.
- **Adapters are selector-based.** Gmail and WhatsApp change their DOM without
  notice; if auto-scan goes quiet on a site, the selectors in
  `extension/content/adapters.js` are the first place to look.

## What changed from V1

| | V1 | V2 |
|---|---|---|
| Backend | FastAPI on localhost:8000 | none — all in-browser |
| Detection | one model | heuristics + URL analysis + brand impersonation + model, fused |
| Input | manual paste | auto-scan with per-site adapters, plus paste and right-click |
| Output | label + confidence | verdict, score, and reasons in plain language |
| Warning | banner for blocked emails | in-page card with reasons and actions, shadow-DOM isolated |
| Sender lists | blocklist | blocklist + allowlist |
| Tests | 17 e2e checks against the backend | 146 engine checks, model parity, measured accuracy gates, 15 browser checks |
