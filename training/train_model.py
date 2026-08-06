"""Train the on-device scam classifier.

The artifact this produces is not served by anything — V2 has no backend. It
is exported to JSON by export_model.py and shipped inside the extension, where
extension/engine/model.js runs inference in the browser.

    python3 train_model.py
    python3 export_model.py
    python3 ../tests/test_parity.py
"""

import json
import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import cross_val_score, train_test_split
from sklearn.pipeline import Pipeline

# Combining marks (Unicode categories Mn/Mc) from the ten primary Indic blocks,
# written out as explicit code point ranges.
#
# scikit-learn's default token_pattern is r"(?u)\b\w\w+\b", and `\w` excludes
# Marks. Devanagari vowel signs *are* Marks, so "खाता" (kha + AA + ta + AA) is
# four characters of which two are word characters, neither adjacent — it
# tokenized to nothing at all, and "आपका" to the fragment "आपक". Every Indic
# script works this way, so the model was reading mangled consonant skeletons
# or nothing whatever the user actually wrote.
#
# Explicit ranges rather than a Unicode property for two reasons:
#
#   * Python's `re` has no \p{M}, and the alternative — the `regex` module —
#     cannot be used here anyway, because TfidfVectorizer compiles
#     token_pattern with `re`. Reaching for it would mean passing a
#     `tokenizer=` callable instead, which joblib then pickles by reference:
#     tests/test_parity.py loads model.joblib in a different process and would
#     have to import this module to unpickle it at all. A string pattern keeps
#     the artifact self-contained, and it keeps the *extension* dependency-free,
#     which is not negotiable.
#
#   * \p{M} is not one fixed set. JavaScript resolves it against whichever
#     Unicode version the engine ships and Python against its own, so the two
#     sides could silently disagree about a code point added in Unicode 13
#     while both looked correct. Literal ranges are the same set in both
#     languages forever, which is exactly what parity needs.
#
# Only marks are added — not whole blocks. The danda "।" (U+0964) lives in the
# Devanagari block and is sentence punctuation, so it must keep splitting
# tokens the way a full stop does.
#
# Escapes, not literal characters: a combining mark standing alone in source
# has nothing to combine with, so editors render these as tofu or stack them
# onto the preceding quote. A range nobody can read is a range nobody can
# review.
#
# This must stay character-for-character identical to INDIC_MARKS in
# extension/lib/text.js. The line grouping is per script in both files so the
# two can be diffed by eye.
INDIC_MARKS = (
    r"\u0900-\u0903\u093A-\u093C\u093E-\u094F\u0951-\u0957\u0962-\u0963"  # Devanagari
    r"\u0981-\u0983\u09BC\u09BE-\u09C4\u09C7-\u09C8\u09CB-\u09CD\u09D7\u09E2-\u09E3\u09FE"  # Bengali
    r"\u0A01-\u0A03\u0A3C\u0A3E-\u0A42\u0A47-\u0A48\u0A4B-\u0A4D\u0A51\u0A70-\u0A71\u0A75"  # Gurmukhi
    r"\u0A81-\u0A83\u0ABC\u0ABE-\u0AC5\u0AC7-\u0AC9\u0ACB-\u0ACD\u0AE2-\u0AE3\u0AFA-\u0AFF"  # Gujarati
    r"\u0B01-\u0B03\u0B3C\u0B3E-\u0B44\u0B47-\u0B48\u0B4B-\u0B4D\u0B55-\u0B57\u0B62-\u0B63"  # Oriya
    r"\u0B82\u0BBE-\u0BC2\u0BC6-\u0BC8\u0BCA-\u0BCD\u0BD7"  # Tamil
    r"\u0C00-\u0C04\u0C3C\u0C3E-\u0C44\u0C46-\u0C48\u0C4A-\u0C4D\u0C55-\u0C56\u0C62-\u0C63"  # Telugu
    r"\u0C81-\u0C83\u0CBC\u0CBE-\u0CC4\u0CC6-\u0CC8\u0CCA-\u0CCD\u0CD5-\u0CD6\u0CE2-\u0CE3\u0CF3"  # Kannada
    r"\u0D00-\u0D03\u0D3B-\u0D3C\u0D3E-\u0D44\u0D46-\u0D48\u0D4A-\u0D4D\u0D57\u0D62-\u0D63"  # Malayalam
    r"\u0D81-\u0D83\u0DCA\u0DCF-\u0DD4\u0DD6\u0DD8-\u0DDF\u0DF2-\u0DF3"  # Sinhala
)

# A token is a word character followed by one or more word-or-Indic-mark
# characters. That is deliberately the smallest possible edit to sklearn's
# default: a mark can only ever *extend* a token that already started on a
# letter, never begin one, so no character outside the ranges above changes
# behaviour. Verified exhaustively rather than by argument — for every code
# point up to U+2FFFF, inserting it between two Latin words changes the token
# list only for the marks listed here, so every existing weight was learned on
# unchanged English text.
#
# The `\b` anchors sklearn uses are dropped, not forgotten. `\w[\w…]+` is
# already maximal-run semantics under findall, and a trailing `\b` would
# actively break the fix: "खाता." ends on a Mark, which is not a word
# character, so there is no word boundary there and the regex would backtrack
# and strip the final vowel sign back off.
TOKEN_PATTERN = rf"(?u)\w[\w{INDIC_MARKS}]+"

df = pd.read_csv("dataset.csv").dropna()
df["label"] = df["label"].astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
)

pipeline = Pipeline([
    # ngram_range (1,2) lets the model see word pairs, so phrases like
    # "do not share" and "share your details" are distinguishable.
    #
    # These settings are load-bearing: extension/engine/model.js re-implements
    # this exact vectorizer in JavaScript. Changing the tokenizer, ngram range,
    # or norm here without updating model.js will silently produce wrong
    # predictions in the extension — tests/test_parity.py catches that.
    # token_pattern replaces sklearn's default so that Indic combining marks
    # stay attached to the letters they modify; see TOKEN_PATTERN above, and
    # tokenize() in extension/lib/text.js, which must match it exactly.
    # min_df=3 drops every term appearing in fewer than three messages. On a
    # corpus of real mail that is most of the vocabulary — 151k terms falls to
    # 24k — and cutting them *raises* accuracy from 94.99% to 96.09%, because a
    # bigram seen once is memorised, not learned. max_features then caps what
    # survives at the size/accuracy knee: 6k terms is 261 KB and scores within
    # 0.12pp of 20k terms at 929 KB.
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, norm="l2",
                              token_pattern=TOKEN_PATTERN,
                              min_df=3, max_features=6000)),
    # class_weight="balanced" matters more than raw accuracy here: missing a
    # scam costs the user money, flagging a real email costs them a click.
    ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
])

pipeline.fit(X_train, y_train)

y_pred = pipeline.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
cv_scores = cross_val_score(pipeline, df["text"], df["label"], cv=5)

print(f"Validation accuracy: {accuracy:.2%}")
print(f"5-fold CV: {cv_scores.mean():.2%} (+/- {cv_scores.std() * 2:.2%})")
print()
print(classification_report(y_test, y_pred, target_names=["legit", "scam"]))
print("Confusion matrix (rows = actual, cols = predicted):")
print(confusion_matrix(y_test, y_pred))

os.makedirs("model", exist_ok=True)
joblib.dump(pipeline, "model/model.joblib")

with open("model/metrics.json", "w", encoding="utf-8") as f:
    json.dump(
        {
            "validation_accuracy": round(float(accuracy), 4),
            "cv_mean": round(float(cv_scores.mean()), 4),
            "cv_std": round(float(cv_scores.std()), 4),
            "rows": int(len(df)),
        },
        f,
        indent=2,
    )

print("\nSaved model/model.joblib and model/metrics.json")
