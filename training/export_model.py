"""Export the trained scikit-learn pipeline to JSON for on-device inference.

The extension ships no Python and no WASM runtime — it re-implements TF-IDF +
logistic regression directly in JavaScript (extension/engine/model.js). This
script writes the only thing that implementation needs: the vocabulary, the
IDF vector, the learned coefficients, and the intercept.

Run after train_model.py:
    python3 export_model.py

Then verify the JS and Python agree:
    python3 ../tests/test_parity.py
"""

import json
import os
from datetime import datetime, timezone

import joblib

MODEL_PATH = "model/model.joblib"
METRICS_PATH = "model/metrics.json"
OUT_PATH = "../extension/engine/model-weights.json"

# Pruning by coefficient is UNSOUND and is deliberately disabled.
#
# The reasoning behind it — "a term with a near-zero coefficient contributes
# nothing to the decision, so it can be dropped" — is true of the dot product
# and false of the vector, because TfidfVectorizer L2-normalizes. Every term
# present in a document, whatever its coefficient, is part of the norm that
# divides all the others. Removing one from the JS vocabulary changes the
# denominator, so *every* feature value shifts and the two implementations
# quietly disagree.
#
# This sat latent until the vocabulary grew enough for two terms ("function",
# "following") to fall under the threshold. A document containing "following"
# then scored 0.1217 in Python and 0.1214 in JS. Small, but it is the exact
# class of silent divergence the parity test exists to catch, and it would
# have grown with the vocabulary.
#
# Size is controlled at training time by max_features instead, which is the
# right place: sklearn then normalizes over the same vocabulary the extension
# ships. Set this above zero only with a matching fix to the norm.
COEF_EPSILON = 0.0


def main() -> None:
    pipeline = joblib.load(MODEL_PATH)
    vectorizer = pipeline.named_steps["tfidf"]
    classifier = pipeline.named_steps["clf"]

    vocabulary = vectorizer.vocabulary_
    idf = vectorizer.idf_
    coef = classifier.coef_[0]
    intercept = float(classifier.intercept_[0])

    ngram_max = vectorizer.ngram_range[1]

    # Re-index so the shipped arrays are dense and contiguous after pruning.
    kept = [(term, idx) for term, idx in vocabulary.items() if abs(coef[idx]) >= COEF_EPSILON]
    kept.sort(key=lambda pair: pair[1])

    new_vocabulary = {}
    new_idf = []
    new_coef = []
    terms = []
    for new_index, (term, old_index) in enumerate(kept):
        new_vocabulary[term] = new_index
        new_idf.append(round(float(idf[old_index]), 6))
        new_coef.append(round(float(coef[old_index]), 6))
        terms.append(term)

    validation_accuracy = None
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, encoding="utf-8") as f:
            validation_accuracy = json.load(f).get("validation_accuracy")

    payload = {
        "version": 2,
        "trainedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ngramMax": ngram_max,
        "vocabSize": len(new_vocabulary),
        "validationAccuracy": validation_accuracy,
        "intercept": round(intercept, 6),
        "vocabulary": new_vocabulary,
        "idf": new_idf,
        "coef": new_coef,
        "terms": terms,
    }

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, separators=(",", ":"))

    size_kb = os.path.getsize(OUT_PATH) / 1024
    dropped = len(vocabulary) - len(new_vocabulary)
    print(f"Wrote {OUT_PATH}")
    print(f"  terms kept: {len(new_vocabulary)} (pruned {dropped} near-zero)")
    print(f"  file size:  {size_kb:.1f} KB")


if __name__ == "__main__":
    main()
