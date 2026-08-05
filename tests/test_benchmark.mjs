// Measured false-positive and false-negative rates for the whole engine.
//
//     node tests/test_benchmark.mjs [--verbose]
//
// test_engine.mjs asks "does this specific case behave correctly". This asks
// "how often is the extension wrong", over every row of the training corpus,
// through the real fused engine rather than the classifier alone. Those are
// different numbers: the model reports 95.5% cross-validated, but the verdict
// a user sees is heuristics and URL analysis and impersonation and the model,
// squashed and thresholded, and nothing was measuring *that*.
//
// It exists because "reduce false positives" is not an actionable goal without
// a number attached. The gates below are deliberately set a little looser than
// the current measurement, so ordinary work doesn't trip them but a real
// regression does.
//
// A caveat worth keeping in view: the corpus rows are also training rows for
// the model layer, so the model is graded on data it has seen. That inflates
// the score, and it is why the gate is a regression alarm rather than a claim
// about accuracy. The honest accuracy number is the cross-validated one that
// train_model.py prints.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const ext = join(root, "extension");

globalThis.chrome = { runtime: { getURL: (p) => join(ext, p) } };
globalThis.fetch = async (path) => ({
  ok: true,
  json: async () => JSON.parse(readFileSync(path, "utf-8")),
});

const { analyzeLocal, VERDICT } = await import(join(ext, "engine", "engine.js"));

const verbose = process.argv.includes("--verbose");

/* ------------------------------ load the corpus ---------------------------- */
// Minimal RFC 4180 parser. The dataset has quoted fields containing commas,
// newlines and doubled quotes, so splitting on commas silently corrupts rows.

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else quoted = false;
      } else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (ch !== "\r") field += ch;
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function load(file) {
  const csv = parseCsv(readFileSync(join(root, "training", file), "utf-8"));
  const header = csv[0];
  const textAt = header.indexOf("text");
  const labelAt = header.indexOf("label");
  return csv
    .slice(1)
    .filter((r) => r.length > labelAt && r[textAt])
    .map((r) => ({ text: r[textAt], scam: r[labelAt].trim() === "1" }));
}

const corpus = load("dataset.csv");

// The curated rows are the scams this tool is *for* — credential requests, UPI
// collect-requests, gift-card demands, digital-arrest threats. They are graded
// separately from the corpus because the corpus's spam is mostly 2002
// commercial advertising, and a marketing email is not what BaitWatch promises
// to catch. Blending them produces one meaningless number: a miss rate of 74%
// that is almost entirely "did not warn about a newsletter".
const curatedScams = load("curated.csv").filter((r) => r.scam);

/* --------------------------------- measure --------------------------------- */

const missed = [];
const falseAlarms = [];
let scams = 0;
let legit = 0;

for (const row of corpus) {
  const result = await analyzeLocal(row.text);
  const flagged = result.verdict !== VERDICT.SAFE;

  if (row.scam) {
    scams += 1;
    if (!flagged) missed.push({ score: result.score, text: row.text });
  } else {
    legit += 1;
    if (flagged) falseAlarms.push({ score: result.score, verdict: result.verdict, text: row.text });
  }
}

const falsePositiveRate = falseAlarms.length / legit;
const falseNegativeRate = missed.length / scams;

// Graded separately — see the note on curatedScams above.
const curatedMissed = [];
for (const row of curatedScams) {
  const result = await analyzeLocal(row.text);
  if (result.verdict === VERDICT.SAFE) curatedMissed.push({ score: result.score, text: row.text });
}
const curatedMissRate = curatedMissed.length / curatedScams.length;

// Legitimate mail called *dangerous* is the worst outcome the extension has:
// suspicious is a note the user can dismiss, dangerous is a red card over
// something real.
const dangerousOnLegit = falseAlarms.filter((f) => f.verdict === VERDICT.DANGEROUS).length;

console.log(`\nCorpus: ${corpus.length} messages (${scams} scam, ${legit} legitimate)\n`);
console.log(`  False positives  ${falseAlarms.length}/${legit}  (${(falsePositiveRate * 100).toFixed(2)}%)`);
console.log(`    of those, "dangerous"  ${dangerousOnLegit}  (${((dangerousOnLegit / legit) * 100).toFixed(2)}%)`);
console.log(`  False negatives  ${missed.length}/${scams}  (${(falseNegativeRate * 100).toFixed(2)}%)`);
console.log(
  `\n  Targeted scams missed  ${curatedMissed.length}/${curatedScams.length}  (${(curatedMissRate * 100).toFixed(2)}%)`
);
console.log("    (curated rows only — the tactics this tool is built for)");

if (verbose) {
  console.log("\nWorst false positives:");
  for (const f of falseAlarms.sort((a, b) => b.score - a.score).slice(0, 10)) {
    console.log(`  ${String(f.score).padStart(3)} ${f.verdict.padEnd(10)} ${JSON.stringify(f.text.slice(0, 90))}`);
  }
  console.log("\nWorst misses:");
  for (const m of missed.sort((a, b) => a.score - b.score).slice(0, 10)) {
    console.log(`  ${String(m.score).padStart(3)} ${JSON.stringify(m.text.slice(0, 90))}`);
  }
}

/* ---------------------------------- gates ---------------------------------- */

// No gate on the corpus-wide false negative rate. It is dominated by 2002
// commercial spam that the extension deliberately does not warn about, so a
// limit on it would be a limit on being wrong in the right direction. It is
// printed, not enforced.
const GATES = [
  ["false positive rate", falsePositiveRate, 0.04],
  ["legitimate mail called dangerous", dangerousOnLegit / legit, 0.01],
  // Currently 15.7%, down from 27.1% before the corpus retrain. The gate sits
  // above that as a regression alarm, not a target — the remaining misses are
  // whole tactics with no rule yet rather than tuning, and they cluster:
  // family-emergency impersonation ("Hi dad, I broke my screen, transfer to
  // this UPI"), failed-delivery redispatch fees, advance-fee job offers,
  // refund/callback scams, and 419-style inheritance letters. All of them
  // score 23-33 against a threshold of 35, with the model already confident.
  // Rules for those are the next thing that moves this number.
  ["targeted scams missed", curatedMissRate, 0.20],
];

let failed = 0;
console.log("");
for (const [name, actual, limit] of GATES) {
  const ok = actual <= limit;
  if (!ok) failed += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}: ${(actual * 100).toFixed(2)}% (limit ${(limit * 100).toFixed(0)}%)`);
}

if (failed) {
  console.log(`\n${failed} gate(s) exceeded.`);
  process.exit(1);
}
console.log("\nAll benchmark gates passed.");
