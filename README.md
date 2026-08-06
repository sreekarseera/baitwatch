# BaitWatch

A Chrome extension that reads the message you already have open — an email in
Gmail, a chat in WhatsApp Web or Telegram Web — and tells you in plain language
what the sender is actually trying to get from you.

Detection runs inside your browser. There is no server, no account, and no
telemetry. Nothing you read is sent anywhere, with exactly one exception: if you
paste in your own Anthropic API key and switch the feature on, messages the
on-device layers cannot settle are sent to Claude for a second opinion. That is
off by default and described in full under [Privacy](#privacy).

```bash
git clone https://github.com/sreekarseera/baitwatch
cd baitwatch
```

Then in Chrome 116 or newer: `chrome://extensions` → enable **Developer mode** →
**Load unpacked** → select the `extension/` folder. No build step, no
`npm install`, no service to start — the model weights are committed.

```bash
python3 tests/run_all.py --no-browser   # everything except the Chrome layer
```

## What it catches

Concretely, these are the things that make it speak up, each with the reason it
shows the user:

| It sees | It says |
|---|---|
| "This is your CEO — buy $500 in Apple gift cards, send me the codes, don't discuss this with anyone" | payment demanded in gift cards; someone claiming to be your boss; a request for secrecy |
| "Your KYC has expired, your account will be blocked today — update now" | manufactured account trouble plus a countdown |
| A link to `paypa1-secure.com`, `arnazon.com`, or Cyrillic `рaypal.com` | the domain is one substitution away from the real one, and it names the brand being imitated |
| A sign-in page titled "HDFC NetBanking" served from `secure-portal-9f2.xyz` | the page claims to be a bank it is not hosted by, and it is asking for a password |
| "Aapka OTP bhejiye, turant" — or the same in Devanagari | a request to hand over a one-time code |
| A courier notice asking for a small re-delivery fee | couriers do not charge you to re-attempt a delivery |

And these are things it deliberately stays quiet about, because a tool that
cries wolf gets uninstalled:

- Ordinary business mail that happens to say "urgent", "immediately", or "final
  reminder".
- Real bank and workplace login pages. "Enter your password" is a credential
  request in a message and the most ordinary sentence in the world on the login
  page it describes.
- "Hi mum, this is my new number" with no request for money attached — a real
  message that real people really send.
- Marketing, newsletters, and offers from senders you actually deal with.

Every warning names its reasons. A score with no reason is useless to the person
who has to make the decision.

## Measured, not asserted

All of these come from `node tests/test_benchmark.mjs`, which runs the whole
fused engine over the project's corpus and fails the build if the rates regress.
Re-run it and you should see the same numbers.

| | |
|---|---|
| Legitimate messages flagged at all | **0.73%** (12 of 1,649) |
| …of those, called *dangerous* rather than *suspicious* | **0.18%** (3 of 1,649) |
| Targeted scams missed | **4.00%** (7 of 175) |
| Hinglish / Devanagari scams missed | **5.71%** (2 of 35) |
| False alarms on ordinary Hinglish | **0** (of 21) |

The honest accuracy figure for the model layer on its own is the cross-validated
one `training/train_model.py` prints: **94.77% ±1.59%** over 3,248 rows, with
95.85% on the held-out split. The benchmark's corpus rows are also training
rows, so it flatters the model — it is a regression alarm, not a claim about
accuracy on mail it has never seen.

The corpus-wide false negative rate is 27.64%, and it is printed but not gated
on purpose. It is dominated by 2002-era commercial advertising that the
extension deliberately does not warn about; not warning you about a newsletter
is the correct behaviour, so a limit on that number would be a limit on being
wrong in the right direction.

## Privacy

The default configuration makes no network requests of any kind. Turn off your
wifi and the extension works exactly the same.

**What is stored, and where.** History (the last 500 verdicts), your blocklist
and allowlist, your settings, and a few counters, all in `chrome.storage.local`
on the machine you are sitting at. Not `chrome.storage.sync`, so none of it
crosses to your other devices via your Google account. History can be exported
to CSV or cleared from the popup.

**The one exception: the Claude second opinion.** It is off by default
(`cloudTier: false` in `extension/lib/storage.js`) and requires two deliberate
actions to turn on — pasting your own Anthropic API key into the options page,
*and* enabling the toggle. Turning on the toggle without a key does nothing and
says so. Once both are set, the extension sends message text to
`api.anthropic.com` only when the local layers landed in the uncertain band
(a fused score between 25 and 80), or when they flagged something with no
human-readable reason to show. Measured over this project's own corpus, that
band covers 16% of the curated scam rows and 32% of the full corpus; your own
mail will differ. The key is yours, is stored only in `chrome.storage.local`,
and is used only for these requests. There is no server in this project, so
there is nowhere else for anything to go.

**Permissions, and why each one is there.**

| Permission | Why |
|---|---|
| `storage` | history, sender lists, settings, API key — all local |
| `contextMenus` | the right-click *Check this text for scams* item |
| `notifications` | showing the verdict of a right-click scan |
| `activeTab`, `scripting` | injecting the scanner into the current tab for *Scan this entire page*. `activeTab` is granted by Chrome only at the moment you click the extension, not ambiently |
| content script on `<all_urls>` | the generic adapter has to already be present to read a message on a site with no dedicated adapter. It hands text to the extension's own service worker in the same browser process |
| host permission `https://api.anthropic.com/*` | the only remote origin this extension is able to reach at all, and only with the second opinion enabled |

There is no `tabs` permission, so the extension cannot enumerate your open tabs
or read their URLs. The whole-page scan works by asking the content script to
report the address of the page it is already running on.

## How it fits together

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

Analysis only ever runs in the service worker. That means the ~262 KB of model
weights are parsed once per browser session rather than once per tab, detection
logic never executes inside a page's origin, and the API key never has to be
exposed to a content script.

Three ways in, depending on what you are looking at:

- **Automatically, as you read.** Dedicated adapters for Gmail, WhatsApp Web and
  Telegram Web; a conservative generic scanner everywhere else.
- **Scan this entire page**, from the popup. This judges everything at once: the
  visible text, every link's actual destination, form targets, and the site's own
  address. It is the one to use on a page that asks you to sign in — a
  credential-harvest page reads "Sign in to continue" and hides the hostile
  domain in the link, so scanning text alone misses the only signal that matters.
- **Right-click a selection** → *Check this text for scams*. The escape hatch for
  canvas-rendered apps and PDFs.

Block a sender and it stays blocked; mark one safe and it stops being flagged.

## How detection works

Four layers, deliberately **not** averaged together.

**1. Heuristics** — 21 rules for the social-engineering tactics that stay
constant across rewrites: OTP and password requests, gift-card
payment, UPI collect-requests, crypto transfers, invoice redirection, boss
impersonation, arrest threats, secrecy demands, remote-access installs,
family-emergency impersonation, failed-delivery fees, advance-fee job offers,
refund-callback traps, and 419-style windfall letters.

The last five came from the benchmark rather than from imagination: they were
the tactics it showed being missed, all scoring 23-33 against a threshold of
35. Adding them took the targeted miss rate from 15.7% to 3.6% on the corpus as
it then stood. It reads 4.00% today against a corpus that has since gained 35
Hinglish and Devanagari rows.

Each is conjunctive, and the near-misses are the reason. "Hi mum, this is my
new number" is a real message people really send; so is "bro, send me the
wedding photos". Only a claimed relationship *and* a request for money *and*
either an unverifiable number or a sudden crisis is the tactic.

**The rules read Hinglish and Devanagari, not only English.** UPI
collect-requests, KYC expiry and digital-arrest threats are Indian tactics, but
matching them in English alone missed 64% of the same scams written in
Roman-script Hindi and **100%** written in Devanagari. Both are now covered:
5.7% missed overall, which is 2 of 25 Roman-script rows and 0 of 10 Devanagari
ones, with no false alarms on ordinary Hinglish.

This works because heuristics run regexes over normalized text and never
tokenize — which is what let this layer cover Devanagari back when the
tokenizer could not see it at all. Two things had to be fixed alongside the
vocabulary:

- The exonerating rule "doesn't ask you to click, pay, or hand over anything"
  tested for the **absence** of English verbs, so it fired on every non-English
  message and handed a discount to precisely the scams the rules were added to
  catch. An absence-based rule has to know every language the presence-based
  ones do, or it quietly inverts.
- The classifier returned a probability just under 0.5 for Hindi it could not
  read, which *subtracted* points. It now abstains below a minimum number of
  recognised terms — "confidently benign" and "I cannot read this" look
  identical in a probability, and only one deserves a vote. That abstention is
  still doing the work, for a different reason: the tokenizer reads Devanagari
  now, but the corpus is too thin in it for the model to have learned anything,
  so a Hindi message still hits no known terms.

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
muttering about character sets. The fold table itself is derived from Unicode's
`confusables.txt` (`tools/build_confusables.py`), so it reaches the letters a
hand-written list stops short of — Greek sigma for `o`, Cyrillic omega for `w`
— rather than only the ones someone thought to type out.

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
V3's CSP makes that a fight), no multi-megabyte runtime, nothing fetched over
the network: 262 KB of weights read straight out of the extension package.

It is trained on 3,248 messages — 336 curated rows plus the SpamAssassin public
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

## Turning on the Claude second opinion

Optional, off by default, and it costs you money rather than the project. Click
the extension → ⚙ → paste an [Anthropic API key](https://console.anthropic.com)
→ **Test** → enable **Ask Claude when the local check is uncertain**. Both steps
are needed; the toggle alone does nothing and tells you so.

From then on, only messages the on-device layers can't settle go to the API, and
the key stays in `chrome.storage.local` on your machine. See
[Privacy](#privacy) for exactly which messages qualify and how often that is.

## Tests

```bash
python3 tests/run_all.py                 # all five suites
python3 tests/run_all.py --no-browser    # skip the Chrome layer
node tests/test_benchmark.mjs --verbose  # what it gets wrong, and how badly
```

| Suite | What it protects |
|---|---|
| Model parity | the JavaScript re-implementation of the classifier still agrees with scikit-learn, across the whole dataset plus adversarial unicode |
| Detection engine | 164 behavioural checks: scams caught, ordinary mail left alone, URL and whole-page logic correct |
| Adapter health | 27 checks that each site adapter's selectors and landmarks still describe the page, and that a broken adapter is reported rather than going quiet |
| Accuracy benchmark | five gates on measured false-positive and miss rates; fails the build on a regression |
| Browser smoke | 15 checks that the extension really loads in Chrome, warns on a real page, and catches a fake sign-in page via its link targets |

`test_engine.mjs` asks whether specific cases behave correctly.
`test_benchmark.mjs` asks how often the extension is wrong, across the whole
corpus, through the real fused engine rather than the classifier alone. Those
gates are what make "reduce false positives" an actionable goal rather than a
feeling.

The first four suites need only Python and Node. The browser layer additionally
needs `pip install websocket-client` and **Chrome for Testing** — branded Google
Chrome 137+ silently refuses to load unpacked extensions from the command line.
See [`tests/README.md`](tests/README.md) for the workaround.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Two invariants are easy to violate by
accident and expensive to violate quietly: **re-run model parity after touching
the tokenizer or the model**, and **use Chrome for Testing for the browser
layer**. Both are explained there.

## Retraining the model

Only needed if you change the dataset. Requires `scikit-learn`, `pandas`,
`joblib`.

```bash
cd training
pip install -r requirements.txt
python3 train_model.py     # trains, prints metrics, writes model.joblib
python3 export_model.py    # writes extension/engine/model-weights.json
cd .. && python3 tests/test_parity.py   # REQUIRED — see CONTRIBUTING.md
```

**Always run the parity test after retraining.** `extension/lib/text.js`
re-implements the tokenizer configured in `train_model.py` by hand. If the two
ever drift apart the extension keeps producing confident, wrong answers with
nothing at runtime to catch it. The test runs the whole dataset plus
adversarial unicode through both implementations and fails on any
disagreement.

It compares tokens as well as probabilities, and the token check is the one
that matters for a script the corpus barely covers. A term with no weight is
absent from the vector either way, so two tokenizers can disagree about every
Devanagari word in a message and still return the same probability — which is
exactly how the Devanagari bug survived as long as it did.

Current model: 95.85% held-out accuracy, 94.77% ±1.59% five-fold CV,
6,000 terms, 262 KB.

## Layout

```
extension/
  engine/      heuristics, URL analysis, impersonation, model inference, Claude tier
  content/     site adapters, DOM scanner, in-page warning UI
  background/  service worker — the only place analysis runs
  popup/       manual check, history, sender lists
  options/     settings, API key, model info
  lib/         storage, text utilities, punycode, confusables table, CSV export
training/      corpus builder, datasets, trainer, JSON exporter, icons
tools/         build scripts for the public suffix list and Unicode confusables
tests/         parity, engine, adapter health, accuracy benchmark, browser smoke
docs/          running progress log, plus archived V1 material
```

## License

BaitWatch is MIT licensed — see [`LICENSE`](LICENSE).

`extension/engine/psl-data.js` is generated from the [Mozilla Public Suffix
List](https://publicsuffix.org/), which is licensed under MPL-2.0. That license
covers the data file alone and does not extend to the rest of the project.
Regenerate it with `python3 tools/build_psl.py`.

`extension/lib/confusables-data.js` is derived from [Unicode's confusables
data](https://www.unicode.org/Public/security/latest/confusables.txt) (UTS #39),
used under the [Unicode Terms of Use](https://www.unicode.org/terms_of_use.html).
Regenerate it with `python3 tools/build_confusables.py`; the script explains
which mappings it keeps and, more importantly, which it refuses to.

## Where it stands

[`docs/PROGRESS.md`](docs/PROGRESS.md) is the running log — what changed,
what it measured, and what is worth doing next.

## Known limits

- **Canvas-rendered apps** (Google Docs, Figma) draw text to a canvas rather
  than the DOM, so nothing can read it. Use right-click → *Check this text for
  scams* on a selection instead.
- **Chrome-internal pages** (`chrome://`, the Web Store) block all extensions
  by design.
- **The corpus is old, and American.** The 2,912 real messages come from the
  SpamAssassin public corpus, which is 2002-2003 mail. Its spam is mostly
  commercial advertising rather than credential phishing, and it has never seen
  a UPI collect-request. The 336 curated rows carry the India-specific tactics,
  and they are the ones the benchmark grades.
- **The last few misses are one-offs.** 4.00% of targeted scams still get
  through, and unlike the clusters that produced the five newest rules these
  no longer share a shape — a payroll-redirect, a pre-approved-loan fee, a
  traffic-fine "settlement". Each would need its own rule for one row of
  benefit, which is how a rule set starts overfitting its own test set.
- **The model still contributes nothing on Devanagari, though it can now read
  it.** The tokenizer used to split words at Unicode Marks, and Devanagari
  vowel signs are Marks, so "खाता" tokenized to nothing and "आपका" to the
  fragment "आपक". Both sides now keep Indic marks attached to their base
  letters and the tokens are correct. The vocabulary is not: the corpus holds
  16 Devanagari rows against 3,248, so no Hindi term appears in the three
  documents `min_df` requires *and* survives the 6,000-feature cap, and the
  model has a weight for exactly zero of them. It abstains, and Hindi-script
  messages still rest on the rule layer alone. This is now a dataset problem,
  and only more Devanagari rows will move it.
- **Transliteration has no fixed spelling.** "bhejiye", "bhejo" and "bhej do"
  are one word, and the rules match a stem list rather than anything
  exhaustive. Spellings nobody thought of will be missed.
- **Homoglyph folding covers the scripts built from Latin letterforms, not
  every script.** The table comes from Unicode's `confusables.txt`, but only
  the mappings that fold onto a single ASCII letter and only from an
  allowlisted set of scripts — Latin, Greek, Coptic, Cyrillic, Armenian, and
  the alphabets designed from Latin type (Cherokee, Lisu, Deseret, Osage).
  Devanagari, Arabic, Hebrew, Thai, Han, Kana and Hangul are excluded on
  purpose: their confusables are shape coincidences rather than twins, and
  Devanagari specifically has to survive intact because the Hindi rules match
  it literally. A lookalike built from one of those scripts is caught by the
  mixed-script signal instead of by name.
- **Adapters are selector-based.** Gmail and WhatsApp change their DOM without
  notice, and when they do, the selectors in `extension/content/adapters.js` are
  the first place to look. The extension no longer fails silently when this
  happens: it distinguishes "this site's selectors have rotted" from "there is
  nothing on this page to scan", warns in the page console, and shows a banner
  in the popup saying auto-scan has stopped working on that site.

## Where it stands

[`docs/PROGRESS.md`](docs/PROGRESS.md) is the running log — what changed,
what it measured, and what is worth doing next.

## History

Originally built for a hackathon by **Sreekar**. V1 was a Chrome extension in
front of a FastAPI backend; V2 removed the backend entirely and moved detection
into the browser.

| | V1 | V2 |
|---|---|---|
| Backend | FastAPI on localhost:8000 | none — all in-browser |
| Detection | one model | heuristics + URL analysis + brand impersonation + model, fused |
| Input | manual paste | auto-scan with per-site adapters, plus paste and right-click |
| Output | label + confidence | verdict, score, and reasons in plain language |
| Warning | banner for blocked emails | in-page card with reasons and actions, shadow-DOM isolated |
| Sender lists | blocklist | blocklist + allowlist |
| Tests | 17 e2e checks against the backend | 164 engine checks, 27 adapter checks, model parity, five accuracy gates, 15 browser checks |

`docs/TASKS_OVERVIEW.md` and `docs/DEMO_SCRIPT.md` are V1 documents, kept as a
record of how the hackathon was organized and labelled as historical. They do
not describe the current code.

## License

BaitWatch is MIT licensed — see [`LICENSE`](LICENSE).

`extension/engine/psl-data.js` is generated from the [Mozilla Public Suffix
List](https://publicsuffix.org/), which is licensed under MPL-2.0. That license
covers the data file alone and does not extend to the rest of the project.
Regenerate it with `python3 tools/build_psl.py`.
