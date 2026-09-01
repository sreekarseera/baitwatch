"""Prove the JavaScript model matches the Python one it was exported from.

The extension re-implements scikit-learn's TF-IDF + logistic regression in
JavaScript. That re-implementation is the single most fragile thing in this
repo: a tokenizer that diverges by one character class produces predictions
that look plausible and are wrong, with nothing to notice it at runtime.

This test feeds the whole dataset (plus adversarial strings that probe the
tokenizer's edges) through both implementations and fails on any meaningful
disagreement.

It compares two things, and the second is not redundant. Probabilities catch
divergence only where the vocabulary happens to cover the terms involved: a
term the model has no weight for is absent from the vector either way, so two
tokenizers that disagree about every word of a script would return identical
numbers and pass. Comparing the token lists directly is the only check that
holds for a script the corpus barely contains — which is the situation for
Devanagari, and precisely the situation in which the tokenizer was quietly
wrong for as long as it was.

    python3 tests/test_parity.py
"""

import json
import os
import subprocess
import sys

import joblib
import pandas as pd

from fold_confusables import fold

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL = os.path.join(REPO, "training", "model", "model.joblib")
DATASET = os.path.join(REPO, "training", "dataset.csv")
HARNESS = os.path.join(REPO, "tests", "parity_harness.mjs")

# Rounding in the exported weights (6 dp) makes exact equality impossible;
# anything tighter than this is far below the threshold granularity the
# engine actually uses.
TOLERANCE = 1e-4

# Strings that specifically probe where a JS tokenizer can diverge from the
# token_pattern in training/train_model.py: unicode letters, digits,
# punctuation, emoji, mixed scripts, and CJK (which that pattern treats as
# word characters).
EDGE_CASES = [
    "",
    "a",
    "OK",
    "URGENT!!! Click here NOW >>> http://bit.ly/x",
    "Your account—suspended. Verify: don't delay!",
    "señor, su cuenta está suspendida",
    "आपका खाता निलंबित कर दिया गया है",
    "口座が停止されました",
    "🚨 URGENT 🚨 verify your account 🔐",
    "user@example.com sent you $500 via UPI",
    "a1 b2 c3 d4 e5",
    "   leading and trailing whitespace   ",
    "CAPS LOCK ENTIRE MESSAGE ABOUT YOUR SUSPENDED ACCOUNT",
    "hyphen-ated co-operate re-verify",
    "under_score snake_case variable_name",
    # Devanagari and its neighbours, where the whole difficulty lives: vowel
    # signs are Unicode Marks, so every one of these words is a run of word
    # characters interrupted by characters that are not. The single word "खाता"
    # is the canonical case — it used to tokenize to nothing at all.
    "खाता",
    "आपका खाता ब्लॉक हो गया है। तुरंत ओटीपी भेजिए।",
    "तुरंत ₹5,000 भेजो वरना खाता बंद हो जाएगा",
    "है को से के में",  # single-syllable words: one letter plus one mark
    "खाता. खाता, खाता! ॥ओम॥",  # marks at a token's end, next to punctuation
    "१२३४ खाता ५६७८",  # Devanagari digits are word characters, its danda is not
    "ँा orphan marks with nothing to attach to",
    # Mixed scripts in one message, which is how these scams are actually
    # written. The Devanagari word between two Latin ones must separate them,
    # exactly as an English word would.
    "आपका KYC खाता block ho gaya hai, verify at http://sbi-kyc.xyz",
    "Dear user, आपका account निलंबित है. Call 1800-123-4567 now",
    "UPI request ₹9,999 स्वीकार करें",
    # Other Indic scripts share the structure, so the same class covers them.
    "ಖಾತೆ ಬ್ಲಾಕ್ ಆಗಿದೆ",
    "வங்கி கணக்கு முடக்கப்பட்டது",
    "আপনার অ্যাকাউন্ট ব্লক",
    "તમારું ખાતું બ્લોક",
    # Latin combining diacritics are Marks too, and are deliberately *not* in
    # the class. These must tokenize exactly as they did before Indic marks
    # were added, or every weight the model learned on English moved under it.
    "état café naïve résumé",  # precomposed
    "e\u0301tat cafe\u0301 nai\u0308ve re\u0301sume\u0301",  # the same words, decomposed
    "aͣb x̸y z̨q",
]


def run_harness(payload: str, extra_args=()):
    """Run the JS harness, returning its stdout lines or None on failure."""
    try:
        result = subprocess.run(
            ["node", HARNESS, *extra_args],
            input=payload,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("FAIL: node not found on PATH — required to test the extension's JS.")
        return None
    except subprocess.CalledProcessError as exc:
        print("FAIL: JS harness errored:\n" + exc.stderr)
        return None
    return result.stdout.strip().split("\n")


def check_tokens(pipeline, texts, payload) -> int:
    """Compare the two tokenizers term for term.

    The tokenizer comes out of the *fitted* vectorizer rather than being
    rebuilt here, so what is tested is the token_pattern actually baked into
    the shipped artifact, not a second copy of it that could be edited to
    agree.
    """
    vectorizer = pipeline.named_steps["tfidf"]
    preprocess = vectorizer.build_preprocessor()  # lowercasing lives here
    tokenize = vectorizer.build_tokenizer()

    lines = run_harness(payload, ["--tokens"])
    if lines is None:
        return 1
    js_tokens = [json.loads(line) for line in lines]

    if len(js_tokens) != len(texts):
        print(f"FAIL: got {len(js_tokens)} JS token lists for {len(texts)} inputs.")
        return 1

    mismatches = []
    for text, js in zip(texts, js_tokens):
        py = tokenize(preprocess(text))
        if py != js:
            mismatches.append((text, py, js))

    print(f"Tokenizers: compared {len(texts)} inputs, {len(mismatches)} disagreed.")
    if mismatches:
        print(f"\nFAIL: {len(mismatches)} input(s) tokenized differently.\n")
        for text, py, js in mismatches[:10]:
            print(f"  {text[:60]!r}\n    py: {py[:12]}\n    js: {js[:12]}")
        print("\ntokenize() in extension/lib/text.js no longer matches the")
        print("token_pattern in training/train_model.py. They are one definition")
        print("kept in two languages and must be edited together.")
        return 1
    return 0


def main() -> int:
    if not os.path.exists(MODEL):
        print("FAIL: training/model/model.joblib missing — run train_model.py first.")
        return 1

    pipeline = joblib.load(MODEL)
    texts = pd.read_csv(DATASET).dropna()["text"].astype(str).tolist() + EDGE_CASES
    payload = "\n".join(json.dumps(t) for t in texts)

    # Tokens first: a tokenizer disagreement is the root cause of almost every
    # probability disagreement, and naming it directly beats reporting a delta
    # of 0.003 on a message and leaving the reader to work out why.
    if check_tokens(pipeline, texts, payload):
        return 1

    # Python side. model.js vectorizes text through normalize(text,
    # {substituteDigits: false}) before tokenizing (commit 715649f), folding
    # Unicode-confusable letters and styled/accented Latin onto plain ASCII so
    # the frozen vocabulary can recognize an obfuscated brand/action word.
    # That's a deliberate divergence from the raw pipeline this test compares
    # against, so fold the same way here or every case that exercises it
    # reads as a false parity failure. See tests/fold_confusables.py.
    py_probs = pipeline.predict_proba([fold(t) for t in texts])[:, 1]

    # JavaScript side — the actual shipped module, via Node.
    lines = run_harness(payload)
    if lines is None:
        return 1
    js_probs = [float(line) for line in lines]

    if len(js_probs) != len(py_probs):
        print(f"FAIL: got {len(js_probs)} JS predictions for {len(py_probs)} inputs.")
        return 1

    mismatches = []
    max_delta = 0.0
    for text, py, js in zip(texts, py_probs, js_probs):
        delta = abs(py - js)
        max_delta = max(max_delta, delta)
        if delta > TOLERANCE:
            mismatches.append((text, py, js, delta))

    print(f"Predictions: compared {len(texts)} inputs ({len(EDGE_CASES)} adversarial).")
    print(f"Largest disagreement: {max_delta:.2e} (tolerance {TOLERANCE:.0e})")

    if mismatches:
        print(f"\nFAIL: {len(mismatches)} prediction(s) diverged.\n")
        for text, py, js, delta in mismatches[:10]:
            preview = text[:60].replace("\n", " ")
            print(f"  Δ={delta:.2e}  py={py:.6f}  js={js:.6f}  {preview!r}")
        print("\nThe JS tokenizer in extension/lib/text.js no longer matches")
        print("scikit-learn's. Fix it before shipping — the model is silently wrong.")
        return 1

    print("\nPASS: JavaScript tokenization and inference match scikit-learn.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
