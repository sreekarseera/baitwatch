# Tests

Six layers, cheapest first. `python3 tests/run_all.py` runs all of them.

| Layer | File | What it protects |
|---|---|---|
| Model parity | `test_parity.py` | The JavaScript re-implementation of the classifier still agrees with scikit-learn |
| Detection engine | `test_engine.mjs` | 164 behavioural checks: scams caught, ordinary mail left alone, URL and whole-page logic correct |
| Adapter health | `test_adapters.mjs` | 29 checks: each adapter's selectors and landmarks still describe its site, and a broken adapter is reported rather than going quiet — without taking the content script down with it |
| Accuracy benchmark | `test_benchmark.mjs` | Five gates on measured false-positive and miss rates, over the whole corpus through the real fused engine |
| Solo-fire gate | `test_ambient.mjs` | A per-rule ceiling on how often each rule convicts legitimate text *alone*, with nothing corroborating it — the rule-shape failure the accuracy gates cannot see |
| Browser smoke | `run_all.py` | 20 checks: the extension loads in Chrome, the packaged model loads under MV3's CSP, a real page gets warned on, and a fake sign-in page is caught via its link targets |

## Why parity is a test and not a comment

`extension/engine/model.js` re-implements scikit-learn's TF-IDF vectorizer and
logistic regression in the browser. If its tokenizer drifts from Python's by one
character class, predictions stay *plausible* and become *wrong*, with nothing at
runtime to notice. `test_parity.py` runs the entire dataset plus 32 adversarial
strings (Devanagari, mixed Devanagari/Latin, other Indic scripts, decomposed
Latin, CJK, emoji, leetspeak, underscores) through both and fails on any
disagreement above 1e-4.

It also compares the token lists themselves, which is not redundant. A term the
model has no weight for is absent from the vector either way, so two tokenizers
can disagree about every word of a script the corpus barely covers and still
return identical probabilities — that is precisely how the Devanagari tokenizer
bug went unnoticed. The tokenizer is taken out of the *fitted* vectorizer, so
what is compared is the pattern baked into the shipped artifact rather than a
second copy of it.

Re-run it after any change to `extension/lib/text.js`, `extension/engine/model.js`,
or the vectorizer settings in `training/train_model.py`. See
[`CONTRIBUTING.md`](../CONTRIBUTING.md) for the full list of triggers.

## What the benchmark is and is not

`test_engine.mjs` asks whether specific cases behave correctly. `test_benchmark.mjs`
asks how often the extension is wrong. Its corpus rows are also training rows for
the model layer, so it grades the model on data it has seen — which is why its
gates are set as a regression alarm rather than published as an accuracy claim.
The honest accuracy number is the cross-validated one `training/train_model.py`
prints.

It also prints a corpus-wide false negative rate that is deliberately not gated.
That number is dominated by 2002-era commercial advertising the extension is not
trying to warn about, so a limit on it would penalise correct behaviour.

## What the solo-fire gate is for

Every rule weighs at least 1.2 and the score curve puts the warning threshold at
a raw weight of 1.12, so **every rule can warn the user firing entirely alone**.
Requiring a second signal is not available — 62% of the scams this tool catches
rest on a single rule — so each rule has to describe an act no legitimate sender
performs. Rules that describe a *topic* instead (arrest, government, prize,
investing) are not sufficient evidence while the scorer treats them as if they
were, and nothing measured which rules those are until this file existed.

`test_ambient.mjs` counts, per rule, how many legitimate rows that rule convicts
with no other signal present, and gates each rule separately against a measured
ceiling. Per-rule and not an aggregate on purpose: an aggregate lets one
catastrophic rule hide behind twenty good ones.

It reads legitimate text only, so **it says nothing about recall**. A rule that
fires on nothing scores perfectly here. Read it next to `test_benchmark.mjs`;
green here and red there is a loss, not a win.

Sources: the 1,834 label-0 rows of `training/dataset.csv`, the hand-written
`tests/ambient-seed.json`, and `tests/holdout-ambient.json` — captured web text
of the kind the extension actually reads, skipped with a message when absent.
Nothing in `tests/holdout-*` may ever enter the training corpus.

```bash
node tests/test_ambient.mjs --verbose   # the rows behind every number
node tests/test_ambient.mjs --baseline  # re-measured limits, ready to paste
```

## Running

```bash
python3 tests/run_all.py                 # everything
python3 tests/run_all.py --no-browser    # skip Chrome (fast; no browser needed)
python3 tests/test_parity.py             # one layer
node tests/test_engine.mjs               # one layer
node tests/test_benchmark.mjs --verbose  # worst false positives and worst misses
```

Layers 1–4 need only Python and Node. Layer 5 additionally needs
`pip install websocket-client` and a Chrome binary.

## The Chrome caveat

Branded **Google Chrome 137+ refuses `--load-extension` entirely** — it prints
`--disable-extensions-except is not allowed in Google Chrome, ignoring` and
carries on without your extension. The smoke test detects this and reports SKIP
rather than a misleading failure. A SKIP is not a pass.

To actually run it, use Chrome for Testing:

```bash
npx @puppeteer/browsers install chrome@stable
CHROME_BIN="/path/to/Google Chrome for Testing" python3 tests/run_all.py
```

## The smoke test owns its ports

The browser layer drives Chrome on port 9223 and serves its fixtures on 8791.
Chrome refuses to start twice on one debugging port and `http.server` exits when
its bind fails, but neither complains anywhere the test can see, so a second
copy of this suite running alongside the first used to adopt the first one's
browser and fixtures — and then report on *that* checkout's extension. Failures
attributed to code that was never loaded are worse than no test at all, so the
run now refuses to start when either port is occupied. Set `BAITWATCH_CDP_PORT`
and `BAITWATCH_PAGES_PORT` to test two checkouts at once.

The test drives a throwaway profile in headless mode — it never touches your
normal Chrome, your tabs, or the extension's stored data.
