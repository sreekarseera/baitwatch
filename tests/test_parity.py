"""Prove the JavaScript model matches the Python one it was exported from.

The extension re-implements scikit-learn's TF-IDF + logistic regression in
JavaScript. That re-implementation is the single most fragile thing in this
repo: a tokenizer that diverges by one character class produces predictions
that look plausible and are wrong, with nothing to notice it at runtime.

This test feeds the whole dataset (plus adversarial strings that probe the
tokenizer's edges) through both implementations and fails on any meaningful
disagreement.

    python3 tests/test_parity.py
"""

import json
import os
import subprocess
import sys

import joblib
import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL = os.path.join(REPO, "training", "model", "model.joblib")
DATASET = os.path.join(REPO, "training", "dataset.csv")
HARNESS = os.path.join(REPO, "tests", "parity_harness.mjs")

# Rounding in the exported weights (6 dp) makes exact equality impossible;
# anything tighter than this is far below the threshold granularity the
# engine actually uses.
TOLERANCE = 1e-4

# Strings that specifically probe where a JS tokenizer can diverge from
# Python's r"(?u)\b\w\w+\b": unicode letters, digits, punctuation, emoji,
# mixed scripts, and CJK (which that pattern treats as word characters).
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
]


def main() -> int:
    if not os.path.exists(MODEL):
        print("FAIL: training/model/model.joblib missing — run train_model.py first.")
        return 1

    pipeline = joblib.load(MODEL)
    texts = pd.read_csv(DATASET).dropna()["text"].astype(str).tolist() + EDGE_CASES

    # Python side.
    py_probs = pipeline.predict_proba(texts)[:, 1]

    # JavaScript side — the actual shipped module, via Node.
    payload = "\n".join(json.dumps(t) for t in texts)
    try:
        result = subprocess.run(
            ["node", HARNESS],
            input=payload,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        print("FAIL: node not found on PATH — required to test the extension's JS.")
        return 1
    except subprocess.CalledProcessError as exc:
        print("FAIL: JS harness errored:\n" + exc.stderr)
        return 1

    js_probs = [float(line) for line in result.stdout.strip().split("\n")]

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

    print(f"Compared {len(texts)} inputs ({len(EDGE_CASES)} adversarial).")
    print(f"Largest disagreement: {max_delta:.2e} (tolerance {TOLERANCE:.0e})")

    if mismatches:
        print(f"\nFAIL: {len(mismatches)} prediction(s) diverged.\n")
        for text, py, js, delta in mismatches[:10]:
            preview = text[:60].replace("\n", " ")
            print(f"  Δ={delta:.2e}  py={py:.6f}  js={js:.6f}  {preview!r}")
        print("\nThe JS tokenizer in extension/lib/text.js no longer matches")
        print("scikit-learn's. Fix it before shipping — the model is silently wrong.")
        return 1

    print("\nPASS: JavaScript inference matches scikit-learn.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
