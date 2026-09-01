// Which rules can convict on their own, measured on legitimate text.
//
//     node tests/test_ambient.mjs [--verbose] [--baseline]
//
// WHAT THIS MEASURES. The score curve is squash(raw) = 100(1 - e^(-raw/2.6)),
// so a raw weight of 1.12 reaches SUSPICIOUS_AT and the lightest rule in the
// set weighs 1.2. Every rule can therefore warn the user firing entirely
// alone. Requiring a second signal is not available as a defence — 62% of the
// scams this tool catches rest on a single rule — so the whole burden falls on
// each rule individually describing an act no legitimate sender performs.
//
// Nothing measured that. A rule that describes a *topic* rather than an act —
// arrest, government, prize, investing — is not sufficient evidence while the
// scorer grants it sufficient authority, and the failure is invisible until a
// user sends a screenshot. This file makes it a number:
//
//   solo-warns    rows where this rule was the ONLY signal that fired and the
//                 score still reached SUSPICIOUS_AT. One unanchored rule, no
//                 corroboration, banner on the user's screen. This is the
//                 number that matters.
//   fires at all  rows where the rule fired for any reason. High is fine on
//                 its own; a rule with 75 fires and 0 solo-warns is behaving
//                 correctly, because something else was always there too.
//
// WHAT IT DOES NOT MEASURE. Recall. Nothing here looks at a scam, and a rule
// that fires on nothing at all scores perfectly. Tightening a rule until this
// suite is green while test_benchmark.mjs goes red is a loss, not a win; the
// two gates have to be read together. It also says nothing about the model or
// the URL layers — see below.
//
// ONE BLIND SPOT WORTH KNOWING. "Solo" means one rule fired, not one word was
// read. Two topic rules keyed to the same vocabulary corroborate each other and
// escape this count entirely: a news report of an arrest trips both
// threat_of_consequence and impersonated_authority, because "police" is in both
// alternations, and so it never appears here however loose either rule is. A
// zero in this table is evidence, not proof.
//
// SCOPE. Rules only, via analyzeHeuristics, not the fused verdict from
// analyzeLocal. That is deliberate on both sides: the model layer is trained on
// the corpus rows this suite reads, so a fused number would be measuring
// memorisation, and a URL or impersonation signal *is* corroboration, which
// would hide exactly the solo convictions being counted. A row counted here
// need not have produced a user-visible warning in production; it means the
// rule layer alone was willing to.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import {
  TESTS,
  installEngineShims,
  loadLabelledCsv,
  loadPageCorpus,
  heuristicsContext,
  squash,
  assertCurve,
} from "./lib/harness.mjs";

installEngineShims();

const here = dirname(fileURLToPath(import.meta.url));
const ext = join(here, "..", "extension");

const { analyzeHeuristics } = await import(join(ext, "engine", "heuristics.js"));
const { THRESHOLDS } = await import(join(ext, "engine", "engine.js"));
const { PROTECTED_BRANDS, registrableDomain, hostOf } = await import(join(ext, "engine", "urls.js"));

const verbose = process.argv.includes("--verbose");
const baselineMode = process.argv.includes("--baseline");

const { SUSPICIOUS_AT, DANGEROUS_AT } = THRESHOLDS;

/* ------------------------- per-rule solo-fire limits ----------------------- */
//
// Maximum solo-warns each rule is allowed on each source. THIS IS A RATCHET:
// every number was measured, not chosen, and it may only ever go down.
//
// Lowering a number here is the normal outcome of tightening a rule — measure,
// then record what you measured. RAISING one is a deliberate act that needs a
// reason written next to it, and it is never the way to clear a red build. A
// red line means a rule that used to need help now convicts legitimate text by
// itself; the fix is in the rule, not in this table. If you genuinely believe
// the new number is correct, say in the comment what act the rule now describes
// that no legitimate sender performs, and why the rows it newly convicts are
// not the ones a user will screenshot.
//
// Rules absent from a table are limited to 0. A new rule, or an existing rule
// that starts solo-firing where it never did, therefore fails on arrival — that
// is the point, and adding it here with a measured number is the deliberate act
// of accepting it.
//
// The gate is per-rule and not an aggregate on purpose. An aggregate lets one
// catastrophic rule hide behind twenty good ones, which is precisely how this
// went unnoticed for a month.
//
// `--baseline` prints the current measurement in this table's own shape, so
// recording a drop after tightening a rule is a paste rather than a
// transcription. It writes nothing: each number is meant to arrive with a
// comment saying what changed.
//
// NEEDS RE-BASELINING: investment_scam, impersonated_authority and
// threat_of_consequence are being converted from topic-shaped to act-shaped as
// this file lands. Their numbers below are the *before* measurement, taken
// 2026-09-01 on commit 31e1b31, and every one of them should fall. Re-run with
// --baseline once that work merges and record what it says; leaving the old
// ceilings in place would let a partly-finished conversion pass.
const LIMITS = {
  // -------------------------------------------------------------------------
  // 1,834 legitimate rows of dataset.csv. Mostly 2002 mailing-list email:
  // political argument, tech support threads, newsletters. Not what the
  // extension reads on a modern page, but it is 1,834 rows of prose written by
  // people with no intent to defraud, which is what this suite needs.
  //
  // Baselined 2026-09-01 against the rules as they stood that morning.
  // -------------------------------------------------------------------------
  corpus: {
    // Topic-shaped, and the worst offender: an ungated conjunction of
    // (invest|trading|stock|ipo) AND (profit|return|scheme) anywhere in the
    // text, which is a description of every financial newsletter ever written.
    // 10 of its 12 fires convict alone.
    investment_scam: 10,
    // A bare list of federal|government|security team|tech support with no
    // gate, so any political or IT thread trips it.
    impersonated_authority: 8,
    // A bare alternation of arrest|court|police|fine. Its false positives are
    // threads titled "Six arrested for attacking Palio jockey".
    threat_of_consequence: 7,
    // The lightest rule in the set at 1.2, which squashes to 37 — three points
    // over the line. Every one of these is a rule weight away from silence.
    artificial_urgency: 4,
    // Act-shaped and included as the control: it demands a transmission or
    // entry verb pointed at the sender, and touches 3 rows in 1,834. This is
    // what the shape of a correct rule looks like in this table.
    credential_request: 3,
    // Post-fix residue. The bare `congratulations` branch went behind
    // CONGRATS_WINDFALL_RE on 2026-09-01; what remains is lottery/inheritance
    // vocabulary in 2002 mail, which was always the rule's real subject. It
    // was 2 before that fix, so this line is what a converted rule looks like.
    prize_or_windfall: 1,
    // Act-shaped and correct — three clauses ANDed, all three required — and
    // it still lands one solo conviction: a book blurb for "HTTP: The
    // Definitive Guide" that happens to contain a transaction word, a contact
    // word and "cancel". Kept at its measured 1 rather than argued about,
    // because a rule that fires once in 1,834 rows is not where the damage is.
    refund_callback: 1,
  },

  // -------------------------------------------------------------------------
  // tests/ambient-seed.json — twelve hand-written pages of the kind the
  // extension actually reads (feed posts, a news report, a newsletter, product
  // and docs pages). Small, and a seed rather than a measurement: it exists so
  // this harness is exercised and reviewable before the real captured corpus
  // lands, and so a rule that starts convicting an ordinary congratulation
  // fails here in under a second.
  // -------------------------------------------------------------------------
  "ambient-seed": {
    // The financial newsletter, at 57 on this rule alone: "IPOs ... returns ...
    // debt fund" trips the ungated (invest|trading|stock|ipo) AND
    // (profit|return|scheme) conjunction, in a post whose actual argument is
    // that nobody can promise a return. This is the diagnosis in one row.
    investment_scam: 1,
    // An ordinary courier tracking page, at 54 alone. The rule wants two of
    // {delivery failed, action demanded, payment mentioned}; the page says the
    // agent "will attempt delivery again tomorrow" and that "no payment is
    // due", so a re-attempt notice and a *negated* payment satisfy two of
    // three. Nothing is asked of the reader anywhere on the page.
    delivery_redispatch_fee: 1,
    // Not listed, and worth saying why: threat_of_consequence fires on 4 of
    // these 12 rows — a news report of an arrest, a thread about a penalty
    // order — and convicts alone on none of them, because something else
    // always fired alongside. That is the shape this table is looking for, and
    // it is not the same claim as "the rule is well gated".
  },

  // -------------------------------------------------------------------------
  // tests/holdout-ambient.json — real captured web text, collected separately
  // and never trained on. Absent as of this commit; the suite skips it.
  //
  // NO MEASURED BASELINE EXISTS, so every rule is limited to 0. That is the
  // standard this corpus is for: it is the text users actually look at, and a
  // rule that convicts a page of it alone is the exact bug this whole file was
  // written about. If it lands red, the red is the finding — read the rows it
  // names before deciding whether the answer is a tighter rule or a measured
  // baseline recorded here with a reason.
  // -------------------------------------------------------------------------
  "ambient-holdout": {},
};

/* --------------------------------- sources --------------------------------- */

const corpusRows = loadLabelledCsv("dataset.csv")
  .filter((r) => !r.scam)
  .map((r) => ({ name: r.text.slice(0, 60), text: r.text, page: null }));

function pageRows(path) {
  const raw = loadPageCorpus(path);
  if (!raw) return null;
  return raw.map((p) => ({ name: p.name || p.site || "(unnamed)", text: p.text, page: p.page }));
}

const SOURCES = [
  {
    key: "corpus",
    label: "legitimate corpus mail",
    detail: "training/dataset.csv, label 0",
    rows: corpusRows,
  },
  {
    key: "ambient-seed",
    label: "ambient seed pages",
    detail: "tests/ambient-seed.json — hand-written, exercises the gate",
    rows: pageRows(join(TESTS, "ambient-seed.json")),
  },
  {
    key: "ambient-holdout",
    label: "ambient held-out pages",
    detail: "tests/holdout-ambient.json — captured web text, never trained on",
    rows: pageRows(join(TESTS, "holdout-ambient.json")),
    skipNote:
      "not collected yet. Nothing in this file may ever enter the training\n" +
      "         corpus; the moment a row is trained on it stops measuring anything.",
  },
];

/* --------------------------------- measure --------------------------------- */

function measure(rows) {
  const solo = new Map();
  const any = new Map();
  const examples = new Map();

  for (const row of rows) {
    const ctx = row.page
      ? heuristicsContext(row.page, { PROTECTED_BRANDS, registrableDomain, hostOf })
      : {};
    const h = analyzeHeuristics(row.text, ctx);

    for (const s of h.signals) any.set(s.id, (any.get(s.id) || 0) + 1);

    // "Only signal that fired" is exactly one incriminating rule. Exonerating
    // rules are counted through the score, not the count: they are not
    // corroboration, they are a discount, and a rule whose solo conviction is
    // cancelled by one has not convicted.
    if (h.signals.length !== 1) continue;
    const score = squash(h.score);
    if (score < SUSPICIOUS_AT) continue;

    const id = h.signals[0].id;
    solo.set(id, (solo.get(id) || 0) + 1);
    if (!examples.has(id)) examples.set(id, []);
    examples.get(id).push({
      score: Math.round(score),
      // Captured pages have a name worth printing; a corpus row's "name" is
      // just the first 60 characters of the text it is printed beside.
      name: row.page ? row.name : "",
      text: row.text,
    });
  }

  return { solo, any, examples };
}

function printTable(source, result) {
  const { solo, any } = result;
  const ids = [...new Set([...any.keys(), ...Object.keys(LIMITS[source.key] || {})])].sort(
    (a, b) => (solo.get(b) || 0) - (solo.get(a) || 0) || (any.get(b) || 0) - (any.get(a) || 0)
  );

  console.log("\n  rule                        solo-warns   fires at all   limit");
  for (const id of ids) {
    const s = solo.get(id) || 0;
    const a = any.get(id) || 0;
    if (s === 0 && a === 0) continue;
    const limit = (LIMITS[source.key] || {})[id] ?? 0;
    const mark = s > limit ? " <-- over" : "";
    console.log(
      `  ${id.padEnd(26)} ${String(s).padStart(6)} ${String(a).padStart(14)}` +
        `${String(limit).padStart(8)}${mark}`
    );
  }

  const total = [...solo.values()].reduce((n, c) => n + c, 0);
  console.log(`\n  ${total} solo conviction(s) across ${result.rowCount} legitimate rows`);
}

/* ---------------------------------- run ------------------------------------ */

const curveProblems = assertCurve(SUSPICIOUS_AT, DANGEROUS_AT);

console.log("\nSolo-fire on legitimate text: can a rule convict with nothing to back it up?");
console.log(
  `  a rule firing alone reaches SUSPICIOUS_AT (${SUSPICIOUS_AT}) at raw weight 1.12; ` +
    "the lightest rule weighs 1.2"
);

const gateLines = [];
let measuredSources = 0;

for (const source of SOURCES) {
  console.log(`\n${source.label}  (${source.detail})`);

  if (source.rows === null) {
    console.log(`  SKIP  ${source.skipNote || "corpus not present"}`);
    continue;
  }
  if (source.rows.length === 0) {
    console.log("  SKIP  corpus is present but empty");
    continue;
  }

  measuredSources += 1;
  const result = measure(source.rows);
  result.rowCount = source.rows.length;
  printTable(source, result);

  const limits = LIMITS[source.key] || {};

  // Every rule's rows under --verbose; otherwise only the ones that broke a
  // limit, because a failing gate is useless without the text that failed it.
  for (const [id, rows] of [...result.examples].sort((a, b) => b[1].length - a[1].length)) {
    if (!verbose && (result.solo.get(id) || 0) <= (limits[id] ?? 0)) continue;
    console.log(`\n  ${id} — convicted alone:`);
    for (const r of rows.slice(0, 5)) {
      console.log(
        `    ${String(r.score).padStart(3)}  ${r.name ? `${r.name}\n         ` : ""}` +
          `${JSON.stringify(r.text.slice(0, 100))}`
      );
    }
    if (rows.length > 5) console.log(`    ... and ${rows.length - 5} more`);
  }

  const ids = [...new Set([...result.solo.keys(), ...Object.keys(limits)])].sort();
  for (const id of ids) {
    const actual = result.solo.get(id) || 0;
    const limit = limits[id] ?? 0;
    gateLines.push({ source: source.key, id, actual, limit });
  }
}

if (baselineMode) {
  // Prints the table in the shape LIMITS wants, so re-baselining after a rule
  // change is a paste rather than a transcription. It does not write anything:
  // recording a new number is meant to be a deliberate edit with a comment.
  console.log("\n--- measured values, for pasting into LIMITS ---");
  for (const source of SOURCES) {
    if (source.rows === null || source.rows.length === 0) continue;
    const { solo } = measure(source.rows);
    const entries = [...solo].filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
    console.log(`  ${JSON.stringify(source.key)}: {`);
    for (const [id, n] of entries) console.log(`    ${id}: ${n},`);
    console.log("  },");
  }
}

/* ---------------------------------- gates ---------------------------------- */

console.log("");
let failed = 0;

for (const problem of curveProblems) {
  failed += 1;
  console.log(`  FAIL  score curve drifted from engine.js: ${problem}`);
}

if (measuredSources === 0) {
  failed += 1;
  console.log("  FAIL  no legitimate corpus was readable — this suite measured nothing");
}

for (const g of gateLines) {
  const ok = g.actual <= g.limit;
  if (!ok) failed += 1;
  console.log(
    `  ${ok ? "PASS" : "FAIL"}  [${g.source}] ${g.id} solo-warns: ${g.actual} (limit ${g.limit})`
  );
}

if (failed) {
  console.log(`\n${failed} solo-fire gate(s) exceeded.`);
  console.log("A rule now convicts legitimate text with nothing corroborating it. Tighten the");
  console.log("rule so it describes an act rather than a topic; raising the limit is not a fix.");
  process.exit(1);
}
console.log("\nAll solo-fire gates passed.");
