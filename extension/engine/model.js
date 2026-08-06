// On-device text classifier.
//
// This is the scikit-learn TF-IDF + logistic regression pipeline from V1,
// exported to plain JSON and re-implemented in ~40 lines of JavaScript. That
// buys three things a runtime like onnxruntime-web would not: no WebAssembly
// (Manifest V3's CSP makes WASM a fight), no multi-megabyte dependency, and
// no network fetch — the whole model is ~260 KB of JSON shipped in the crx.
//
// The tokenizer here must match scikit-learn's exactly or the weights are
// meaningless. tests/test_parity.py asserts that Python and JS agree on every
// row of the training set; treat a parity failure as a broken build.

import { tokenize } from "../lib/text.js";

let weightsPromise = null;

async function loadWeights() {
  if (!weightsPromise) {
    weightsPromise = fetch(chrome.runtime.getURL("engine/model-weights.json")).then((r) => {
      if (!r.ok) throw new Error(`model-weights.json failed to load (${r.status})`);
      return r.json();
    });
  }
  return weightsPromise;
}

/**
 * Build the L2-normalized TF-IDF vector for one document, matching
 * sklearn's TfidfVectorizer defaults (sublinear_tf=False, norm="l2",
 * smooth_idf=True — the smoothing is already baked into the exported idf).
 */
function vectorize(text, { vocabulary, idf, ngramMax }) {
  const tokens = tokenize(text);
  const counts = new Map();

  for (let n = 1; n <= ngramMax; n++) {
    for (let i = 0; i + n <= tokens.length; i++) {
      const term = tokens.slice(i, i + n).join(" ");
      const index = vocabulary[term];
      if (index !== undefined) counts.set(index, (counts.get(index) || 0) + 1);
    }
  }

  let sumSquares = 0;
  const vector = new Map();
  for (const [index, count] of counts) {
    const value = count * idf[index];
    vector.set(index, value);
    sumSquares += value * value;
  }

  const norm = Math.sqrt(sumSquares);
  if (norm > 0) {
    for (const [index, value] of vector) vector.set(index, value / norm);
  }
  return vector;
}

function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

/**
 * @returns {Promise<{probability: number, matchedTerms: Array<{term, weight}>}>}
 *   probability is P(scam). matchedTerms are the highest-contributing terms
 *   present in this message, used to explain the verdict.
 */
export async function classify(text) {
  const weights = await loadWeights();
  const vector = vectorize(text, weights);

  let z = weights.intercept;
  const contributions = [];
  for (const [index, value] of vector) {
    const contribution = value * weights.coef[index];
    z += contribution;
    if (contribution > 0) {
      contributions.push({ term: weights.terms[index], weight: contribution });
    }
  }

  contributions.sort((a, b) => b.weight - a.weight);
  return {
    probability: sigmoid(z),
    matchedTerms: contributions.slice(0, 5),
    // How many vocabulary terms the document actually hit. The caller needs
    // this to tell "confidently benign" from "I have no idea what this says":
    // both come back as a probability near the intercept, but only one of them
    // deserves a vote. Devanagari is the case that forced it — a Hindi scam
    // yields almost no known terms, a probability just under 0.5, and a
    // *negative* pull that pushed real scams back below the warning threshold.
    //
    // The tokenizer used to be the reason; it could not see Hindi script at
    // all. It can now, and this still matters, because the cause moved rather
    // than went away: the corpus holds 16 Devanagari rows, too few to survive
    // min_df=3 and a 6,000-feature cap, so not one Hindi term has a weight.
    // Correct tokens the model has never been taught still come back as zero
    // known terms, and abstaining is still the only honest answer.
    knownTerms: vector.size,
  };
}

// Exposed so the options page can report which model build is loaded, and so
// tests can assert the shipped artifact matches the trained one.
export async function modelInfo() {
  const { version, trainedAt, vocabSize, validationAccuracy } = await loadWeights();
  return { version, trainedAt, vocabSize, validationAccuracy };
}
