// False-positive rate on legitimate mail the model has never seen.
//
//     node tests/test_holdout.mjs [--verbose]
//
// test_benchmark.mjs grades the model on rows it trained on, so its false
// positive number is optimistic by construction — it says so itself. This file
// is the held-out counterpart: modern legitimate messages of the kind users
// actually receive (bank OTPs, order updates, SaaS verification mail, sign-in
// alerts, real promotional newsletters), none of which appear in dataset.csv.
//
// Nothing here may be added to the training corpus. The moment a row is trained
// on, it stops measuring what this file exists to measure.

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

function parseCsv(text) {
  // Only lines *before any CSV content starts* are comments (source/license
  // attribution). Filtering every "#"-led line anywhere, unconditionally, would
  // corrupt a multi-line quoted field whose message text happens to contain a
  // line starting with "#" (a hashtag, a numbered "#3 step" list item) — this
  // stops at the first non-"#" line instead, so it can only ever remove a
  // contiguous header block, never reach into the data that follows it.
  const lines = text.split("\n");
  let firstContentLine = 0;
  while (firstContentLine < lines.length && lines[firstContentLine].startsWith("#")) {
    firstContentLine += 1;
  }
  text = lines.slice(firstContentLine).join("\n");
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

const csv = parseCsv(readFileSync(join(here, "holdout-legit.csv"), "utf-8"));
const header = csv[0];
const genreAt = header.indexOf("genre");
const textAt = header.indexOf("text");
const rows = csv
  .slice(1)
  .filter((r) => r.length > textAt && r[textAt])
  .map((r) => ({ genre: r[genreAt], text: r[textAt] }));

const byGenre = new Map();
const flagged = [];

for (const row of rows) {
  const result = await analyzeLocal(row.text);
  const isFlagged = result.verdict !== VERDICT.SAFE;
  if (!byGenre.has(row.genre)) byGenre.set(row.genre, { total: 0, flagged: 0, dangerous: 0 });
  const bucket = byGenre.get(row.genre);
  bucket.total += 1;
  if (isFlagged) {
    bucket.flagged += 1;
    if (result.verdict === VERDICT.DANGEROUS) bucket.dangerous += 1;
    flagged.push({ ...row, score: result.score, verdict: result.verdict, reasons: result.reasons });
  }
}

const dangerous = flagged.filter((f) => f.verdict === VERDICT.DANGEROUS).length;
const rate = flagged.length / rows.length;
const dangerousRate = dangerous / rows.length;

console.log(`\nHeld-out legitimate mail: ${rows.length} messages (never trained on)\n`);
console.log(`  Flagged            ${flagged.length}/${rows.length}  (${(rate * 100).toFixed(2)}%)`);
console.log(`    of those, "dangerous"  ${dangerous}  (${(dangerousRate * 100).toFixed(2)}%)`);

console.log("\n  By genre:");
for (const [genre, b] of [...byGenre].sort((a, b) => b[1].flagged - a[1].flagged)) {
  const mark = b.flagged === 0 ? "  ok " : "FLAG ";
  console.log(`    ${mark} ${genre.padEnd(15)} ${b.flagged}/${b.total}` + (b.dangerous ? `  (${b.dangerous} dangerous)` : ""));
}

if (flagged.length) {
  console.log("\n  Flagged messages, worst first:");
  for (const f of flagged.sort((a, b) => b.score - a.score)) {
    console.log(`\n    ${String(f.score).padStart(3)} ${f.verdict.padEnd(10)} [${f.genre}]`);
    console.log(`        ${JSON.stringify(f.text.slice(0, 110))}`);
    if (verbose) for (const r of f.reasons) console.log(`        - ${r.id}: ${r.detail}`);
    else for (const r of f.reasons) console.log(`        - ${r.id}`);
  }
}

/* ------------------------- real websites, whole-page ----------------------- */
// The other half of what users scan. A page is not a message: it is nav
// chrome, form labels and legal boilerplate, and a bank's own login page
// necessarily says "password", "OTP" and "never share these with anyone".

const pages = JSON.parse(readFileSync(join(here, "holdout-pages.json"), "utf-8"));
const pageFlags = [];

for (const p of pages) {
  const result = await analyzeLocal(p.text, { extraUrls: [p.page.url], page: p.page });
  if (result.verdict !== VERDICT.SAFE) {
    pageFlags.push({ ...p, score: result.score, verdict: result.verdict, reasons: result.reasons });
  }
}

const pageRate = pageFlags.length / pages.length;

console.log(`\nHeld-out real websites: ${pages.length} pages\n`);
console.log(`  Flagged            ${pageFlags.length}/${pages.length}  (${(pageRate * 100).toFixed(2)}%)`);
for (const f of pageFlags.sort((a, b) => b.score - a.score)) {
  console.log(`\n    ${String(f.score).padStart(3)} ${f.verdict.padEnd(10)} ${f.name}  (${f.page.url})`);
  for (const r of f.reasons) console.log(`        - ${r.id}${verbose ? `: ${r.detail}` : ""}`);
}

/* ------------------------------ real scams, missed -------------------------- */
// The other failure mode: real scams the model has never trained on that it fails
// to catch. tests/holdout-scams.csv is a real, sourced corpus (see the comment at
// the top of that file for provenance and license) — not fabricated or paraphrased.
// A row counts as "missed" when analyzeLocal comes back VERDICT.SAFE on a message
// that is, in fact, a scam.

const scamCsv = parseCsv(readFileSync(join(here, "holdout-scams.csv"), "utf-8"));
const scamHeader = scamCsv[0];
const scamGenreAt = scamHeader.indexOf("genre");
const scamTextAt = scamHeader.indexOf("text");
const scamRows = scamCsv
  .slice(1)
  .filter((r) => r.length > scamTextAt && r[scamTextAt])
  .map((r) => ({ genre: r[scamGenreAt], text: r[scamTextAt] }));

const scamByGenre = new Map();
const missed = [];

for (const row of scamRows) {
  const result = await analyzeLocal(row.text);
  const isMissed = result.verdict === VERDICT.SAFE;
  if (!scamByGenre.has(row.genre)) scamByGenre.set(row.genre, { total: 0, missed: 0 });
  const bucket = scamByGenre.get(row.genre);
  bucket.total += 1;
  if (isMissed) {
    bucket.missed += 1;
    missed.push({ ...row, score: result.score, verdict: result.verdict, reasons: result.reasons });
  }
}

const missRate = missed.length / scamRows.length;

console.log(`\nHeld-out real scams: ${scamRows.length} messages (never trained on)\n`);
console.log(`  Missed (came back SAFE)   ${missed.length}/${scamRows.length}  (${(missRate * 100).toFixed(2)}%)`);

console.log("\n  By genre:");
for (const [genre, b] of [...scamByGenre].sort((a, b) => b[1].missed - a[1].missed)) {
  const mark = b.missed === 0 ? "  ok " : "MISS ";
  console.log(`    ${mark} ${genre.padEnd(30)} ${b.missed}/${b.total}`);
}

if (missed.length) {
  console.log("\n  Missed scams, closest calls first:");
  for (const m of missed.sort((a, b) => b.score - a.score)) {
    console.log(`\n    ${String(m.score).padStart(3)} ${m.verdict.padEnd(10)} [${m.genre}]`);
    console.log(`        ${JSON.stringify(m.text.slice(0, 110))}`);
    if (verbose) for (const r of m.reasons) console.log(`        - ${r.id}: ${r.detail}`);
    else for (const r of m.reasons) console.log(`        - ${r.id}`);
  }
}

/* ---------------------------------- gates ---------------------------------- */

const GATES = [
  ["held-out false positive rate", rate, 0.06],
  ["held-out legitimate mail called dangerous", dangerousRate, 0.0],
  ["held-out real websites flagged", pageRate, 0.0],
  // Measured 35/55 (63.64%) against tests/holdout-scams.csv on 2026-09-01. That's the
  // honest number: this real, unseen corpus skews toward premium-rate/subscription and
  // prize-claim tactics the current rules barely cover (premium_rate_subscription_trap
  // missed 7/7, windfall_solicitation 10/11) versus the credential/UPI/crypto/gift-card
  // tactics the rules were built around. The limit below is one miss of headroom above
  // that measurement, not a loosened target — it exists to catch regressions, not to
  // hide the current miss rate.
  ["held-out real scam miss rate", missRate, 0.65],
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
console.log("\nAll held-out gates passed.");
