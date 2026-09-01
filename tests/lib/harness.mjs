// Shared plumbing for the Node-side test suites.
//
// Three things every suite that runs the shipped engine outside Chrome needs,
// and which existed as three separate copies before this file: the
// `globalThis.chrome` / `globalThis.fetch` shims that let engine/model.js load
// its weights from disk, an RFC 4180 CSV reader (the corpus has quoted fields
// containing commas, newlines and doubled quotes, so splitting on commas
// silently corrupts rows), and the corpus loaders.
//
// test_benchmark.mjs, test_holdout.mjs and parity_harness.mjs still carry their
// own copies. That is deliberate, not an oversight: rules are being edited
// concurrently, and a baseline that moved because a helper was swapped
// underneath it would be indistinguishable from a regression. Migrating them is
// a separate change, to be made when the numbers are quiet, and it should be
// made by asserting the outputs are byte-identical before and after.

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export const REPO = join(here, "..", "..");
export const TESTS = join(REPO, "tests");
export const EXTENSION = join(REPO, "extension");

/**
 * Make the shipped engine importable under Node.
 *
 * engine/model.js reads its weights with `fetch(chrome.runtime.getURL(...))`.
 * Both are browser APIs; stubbing them here means the suites exercise the
 * exact file that ships rather than a copy of it. Must be called before the
 * first `import()` of anything under extension/engine.
 */
export function installEngineShims() {
  globalThis.chrome = { runtime: { getURL: (p) => join(EXTENSION, p) } };
  globalThis.fetch = async (path) => ({
    ok: true,
    json: async () => JSON.parse(readFileSync(path, "utf-8")),
  });
}

/** Minimal RFC 4180 parser. Returns rows of raw string fields. */
export function parseCsv(text) {
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

/**
 * Read a labelled corpus file out of training/ as {text, scam} rows.
 * Same shape the benchmark reads, so the two agree on what a row is.
 */
export function loadLabelledCsv(file) {
  const csv = parseCsv(readFileSync(join(REPO, "training", file), "utf-8"));
  const header = csv[0];
  const textAt = header.indexOf("text");
  const labelAt = header.indexOf("label");
  return csv
    .slice(1)
    .filter((r) => r.length > labelAt && r[textAt])
    .map((r) => ({ text: r[textAt], scam: r[labelAt].trim() === "1" }));
}

/**
 * Read a captured-page corpus (tests/holdout-pages.json, tests/*-ambient.json).
 * Returns null when the file is absent, so a suite can skip rather than crash
 * on a corpus that has not been collected yet.
 */
export function loadPageCorpus(path) {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf-8"));
}

/**
 * The context analyzeHeuristics receives inside analyzeLocal.
 *
 * Two rules read it: credential_request looks at whether the page carries a
 * real credential field, and impersonated_authority stands down on the
 * authority's own registrable domain — saying "Government of India" is a claim
 * of identity in a message and a statement of fact on incometax.gov.in.
 * Measuring rule shape without this would charge a bank's own login page for
 * being a bank.
 *
 * Mirrors engine.js:analyzeLocal. It is reconstructed rather than imported
 * because engine.js builds it inline; the brand list and the domain helpers it
 * uses are the shipped ones.
 */
export function heuristicsContext(page, { PROTECTED_BRANDS, registrableDomain, hostOf }) {
  const pageDomain = page?.url ? registrableDomain(hostOf(page.url) || "") : "";
  return {
    hasCredentialForm: (page?.credentialFields || []).length > 0,
    onOfficialDomain:
      Boolean(pageDomain) && PROTECTED_BRANDS.some((brand) => brand.domains.includes(pageDomain)),
  };
}

/**
 * The score curve, mirrored from engine.js.
 *
 * engine.js does not export `squash`, and this file may not modify the engine,
 * so the constant lives in two places. If the curve there changes, the numbers
 * printed by any suite using this helper become wrong rather than merely
 * stale — assertCurve() below is the tripwire for that.
 */
export const squash = (raw) => 100 * (1 - Math.exp(-raw / 2.6));

/**
 * Sanity check on the mirrored curve: a raw weight of 1.12 is the documented
 * inverse of SUSPICIOUS_AT = 35, and 2.73 of DANGEROUS_AT = 65. If someone
 * retunes the curve in engine.js without touching this file, these stop
 * agreeing and the suite says so instead of quietly reporting fiction.
 */
export function assertCurve(SUSPICIOUS_AT, DANGEROUS_AT) {
  const problems = [];
  if (Math.abs(squash(1.12) - SUSPICIOUS_AT) > 0.5) {
    problems.push(`raw 1.12 should squash to ~${SUSPICIOUS_AT}, got ${squash(1.12).toFixed(2)}`);
  }
  if (Math.abs(squash(2.73) - DANGEROUS_AT) > 0.5) {
    problems.push(`raw 2.73 should squash to ~${DANGEROUS_AT}, got ${squash(2.73).toFixed(2)}`);
  }
  return problems;
}
