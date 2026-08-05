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
const curatedScams = [...load("curated.csv"), ...load("curated-hinglish.csv")].filter((r) => r.scam);

// Roman-script Hindi is how most Indian scam messages are actually written, and
// Devanagari is graded separately from it because the two fail differently: the
// rules cover both, but the model layer is blind to Hindi script entirely.
const DEVANAGARI = /[\u0900-\u097F]/;

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

const indic = [...load("curated-hinglish.csv")];
const indicScams = indic.filter((r) => r.scam);
let indicMissed = 0;
let indicFalseAlarms = 0;
const byScript = {
  roman: { total: 0, missed: 0 },
  devanagari: { total: 0, missed: 0 },
};
for (const row of indic) {
  const result = await analyzeLocal(row.text);
  const flagged = result.verdict !== VERDICT.SAFE;
  if (row.scam) {
    const bucket = byScript[DEVANAGARI.test(row.text) ? "devanagari" : "roman"];
    bucket.total += 1;
    if (!flagged) {
      indicMissed += 1;
      bucket.missed += 1;
    }
  } else if (flagged) indicFalseAlarms += 1;
}
const indicMissRate = indicMissed / indicScams.length;

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
console.log(
  `\n  Hinglish/Hindi scams missed  ${indicMissed}/${indicScams.length}  (${(indicMissRate * 100).toFixed(2)}%)`
);
console.log(
  `    roman script  ${byScript.roman.missed}/${byScript.roman.total}` +
    `    devanagari  ${byScript.devanagari.missed}/${byScript.devanagari.total}`
);
console.log(`    false alarms on ordinary Hinglish  ${indicFalseAlarms}/${indic.length - indicScams.length}`);

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
  // Tightened from 4%/1% once the measurement settled at 0.49%/0.25%. A gate
  // eight times looser than reality is not a gate: it leaves room for a new
  // rule to spend a large amount of accuracy quietly and still pass.
  ["false positive rate", falsePositiveRate, 0.015],
  ["legitimate mail called dangerous", dangerousOnLegit / legit, 0.006],
  // 27.1% before the corpus retrain, 15.7% after it, 3.6% once the five
  // missing tactics got rules. What remains is five messages that are each a
  // different one-off — a payroll-redirect, a pre-approved-loan fee, a traffic
  // fine "settlement" — rather than another cluster worth a rule.
  ["targeted scams missed", curatedMissRate, 0.08],
  // Was 74% before the rules learned any Hindi at all. Gated separately
  // because a blended number hides it: 35 Hinglish rows against 140 English
  // ones can go entirely wrong while the combined figure barely moves.
  ["Hinglish/Hindi scams missed", indicMissRate, 0.20],
  ["false alarms on ordinary Hinglish", indicFalseAlarms / (indic.length - indicScams.length), 0.05],
];

let failed = 0;
console.log("");
for (const [name, actual, limit] of GATES) {
  const ok = actual <= limit;
  if (!ok) failed += 1;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}: ${(actual * 100).toFixed(2)}% (limit ${(limit * 100).toFixed(2)}%)`);
}

if (failed) {
  console.log(`\n${failed} gate(s) exceeded.`);
  process.exit(1);
}
console.log("\nAll benchmark gates passed.");
