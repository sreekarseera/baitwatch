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
    # min_df=3 drops every term appearing in fewer than three messages. On a
    # corpus of real mail that is most of the vocabulary — 151k terms falls to
    # 24k — and cutting them *raises* accuracy from 94.99% to 96.09%, because a
    # bigram seen once is memorised, not learned. max_features then caps what
    # survives at the size/accuracy knee: 6k terms is 261 KB and scores within
    # 0.12pp of 20k terms at 929 KB.
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, norm="l2",
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
