# Tests

Three layers, cheapest first. `python3 tests/run_all.py` runs all of them.

| Layer | File | What it protects |
|---|---|---|
| Model parity | `test_parity.py` | The JavaScript re-implementation of the classifier still agrees with scikit-learn |
| Detection engine | `test_engine.mjs` | 61 behavioural checks: scams caught, ordinary mail left alone, URL and whole-page logic correct |
| Browser smoke | `run_all.py` | 15 checks: the extension loads in Chrome, warns on a real page, and catches a fake sign-in page via its link targets |

## Why parity is a test and not a comment

`extension/engine/model.js` re-implements scikit-learn's TF-IDF vectorizer and
logistic regression in the browser. If its tokenizer drifts from Python's by one
character class, predictions stay *plausible* and become *wrong*, with nothing at
runtime to notice. `test_parity.py` runs the entire dataset plus 15 adversarial
strings (Devanagari, CJK, emoji, leetspeak, underscores) through both and fails
on any disagreement above 1e-4.

Re-run it after any change to `extension/lib/text.js`, `extension/engine/model.js`,
or the vectorizer settings in `training/train_model.py`.

## Running

```bash
python3 tests/run_all.py                 # everything
python3 tests/run_all.py --no-browser    # skip Chrome (fast; no browser needed)
python3 tests/test_parity.py             # one layer
node tests/test_engine.mjs               # one layer
```

Layers 1–2 need only Python and Node. Layer 3 additionally needs
`pip install websocket-client` and a Chrome binary.

## The Chrome caveat

Branded **Google Chrome 137+ refuses `--load-extension` entirely** — it prints
`--disable-extensions-except is not allowed in Google Chrome, ignoring` and
carries on without your extension. The smoke test detects this and reports SKIP
rather than a misleading failure.

To actually run it, use Chrome for Testing:

```bash
npx @puppeteer/browsers install chrome@stable
CHROME_BIN="/path/to/Google Chrome for Testing" python3 tests/run_all.py
```

The test drives a throwaway profile in headless mode — it never touches your
normal Chrome, your tabs, or the extension's stored data.
