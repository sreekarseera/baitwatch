# Contributing

Patches are welcome. The project is small enough that there is no process to
learn: fork, branch, run the tests, open a pull request that says what it
measured. `main` is protected, so everything arrives that way.

Before anything else, get a green run:

```bash
python3 tests/run_all.py --no-browser
```

That is five suites minus the Chrome layer, and it needs only Python and Node.
If it is not green before your change, it is not your change that broke it.

## Two invariants

Almost everything in this repository is safe to get wrong, because a test will
tell you. These two are the exceptions — one because the failure is silent, one
because the tool that should catch it lies to you about why it didn't.

### 1. Re-run model parity after touching the tokenizer or the model

`extension/engine/model.js` and `extension/lib/text.js` re-implement
scikit-learn's TF-IDF vectorizer and logistic regression by hand, so that the
extension can run inference without shipping a WebAssembly runtime. The weights
are exported from Python; the arithmetic that consumes them is JavaScript. If
the two implementations drift apart by one character class, predictions do not
crash and do not look wrong. They stay entirely plausible and become quietly
incorrect, and there is nothing at runtime that can notice.

So after any change to:

- `extension/lib/text.js` — especially `tokenize()`, whose regex mirrors
  scikit-learn's default `token_pattern` of `(?u)\b\w\w+\b`
- `extension/engine/model.js` — the vectorizer or the inference arithmetic
- the `TfidfVectorizer` settings in `training/train_model.py` — `ngram_range`,
  `lowercase`, `norm`, `min_df`, `max_features`
- `training/export_model.py` — anything about how weights are serialized or
  pruned
- the dataset, followed by a retrain

run:

```bash
python3 tests/test_parity.py
```

It pushes every row of the dataset plus 15 adversarial strings (Devanagari, CJK,
emoji, leetspeak, underscores) through both implementations and fails on any
disagreement above 1e-4. A parity failure is a broken build, not a flaky test.

Two things worth knowing before you go near this. First, `export_model.py` once
pruned near-zero-coefficient terms from the exported vocabulary; that is safe for
the dot product and wrong for the vector, because TF-IDF is L2-normalized and
every present term is part of the norm. It stayed latent until two terms crossed
the threshold, and the parity test is what caught it. Second, parity currently
passes on Devanagari for an uncomfortable reason: both implementations split
tokens at Unicode Marks, Devanagari vowel signs are Marks, and so `"खाता"`
tokenizes to nothing in both. They agree because they are wrong identically.
Fixing that means changing the token pattern on **both** sides in lockstep and
retraining — parity is the safety net for exactly that operation, and it has to
stay green through it.

### 2. The browser layer needs Chrome for Testing

Branded Google Chrome 137 and later refuses `--load-extension` outright. It does
not error. It prints

```
--disable-extensions-except is not allowed in Google Chrome, ignoring
```

into its own log and starts up perfectly happily without your extension, at
which point every browser assertion fails for a reason that has nothing to do
with your change. `tests/run_all.py` detects this specific case and reports SKIP
with the fix rather than a misleading failure, but a SKIP is not a pass — if you
have touched anything in `extension/content/`, `extension/background/`, or the
manifest, you need those 15 checks to actually run.

```bash
npx @puppeteer/browsers install chrome@stable
CHROME_BIN="/path/to/Google Chrome for Testing" python3 tests/run_all.py
```

The test drives a throwaway profile in headless mode. It never touches your
normal Chrome, your tabs, or the extension's stored data.

## Adding a detection rule

New heuristics go in `extension/engine/heuristics.js`. Three things the existing
rules will not tell you until you have been bitten:

- **Rules must be conjunctive.** A single-signal rule flags ordinary mail.
  "urgent" is in real emails, "account" is in real emails, and a countdown next
  to a request for a password is not. Look at `family_emergency` for the shape:
  a claimed relationship *and* a request for money *and* either an unverifiable
  number or a crisis.
- **Never match `\d`.** `normalize()` folds digits onto letters to defeat
  homoglyph tricks, so `8000` reaches your rule as `8ooo` and `500` as `soo`.
  Identify an amount by the words around it, not the number.
- **Watch a trailing `\b` after a stem.** `reschedul\b` can never match
  "reschedule" — it demands a word boundary between "l" and "e".

Then justify it with the benchmark rather than with intuition:

```bash
node tests/test_benchmark.mjs --verbose
```

`--verbose` prints the worst false positives and the worst misses. The five most
recent rules were chosen from that output — they were the tactics being missed
at scores of 23-33 against a warning threshold of 35 — and that is the standard
for a new one. A rule that fixes one row and costs false positives is a bad
trade; the gates in `test_benchmark.mjs` will say so.

## Adding a site adapter

Adapters live in `extension/content/adapters.js` and answer one question: where
on this page is "a message"? Each returns `{id, element, text, sender}`, and `id`
must be stable across re-scans of the same message, or the scanner re-analyzes
the same email every time the page mutates — which on Gmail is constantly.

Alongside its selectors, an adapter declares landmarks: page structure that
proves the adapter is on the right site and looking at a loaded page. That is
what lets the health monitor tell "this site's selectors have rotted" apart from
"there is nothing on this page to scan", so a Gmail redesign surfaces as a
warning instead of auto-scan going quiet. `tests/test_adapters.mjs` covers this;
run it after any adapter change.

## Style

The prose in this repository explains *why*, in complete sentences, without
marketing voice. Code comments do the same: they document the reasoning and the
measurements behind a decision, not what the next line does. Several of them
exist purely to stop someone re-introducing a bug that was expensive to find. If
you change behaviour that a comment justifies, update the comment in the same
commit — a stale explanation is worse than none, because it is believed.

Commit messages are written in the imperative and say what changed and what it
measured, not which files were touched.
