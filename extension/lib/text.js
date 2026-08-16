// Text utilities shared by the engine, content scripts, and popup.
// Kept dependency-free so content scripts can use the same code as the popup.

import { CONFUSABLES, CONFUSABLE_RE } from "./confusables-data.js";

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

// Matches http(s) URLs and bare domains like "secure-login.co/verify".
const URL_RE =
  /\b(?:https?:\/\/|www\.)[^\s<>"')]+|\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?:\/[^\s<>"')]*)?/gi;

const PHONE_RE = /(?:\+?\d[\d\s().-]{7,}\d)/g;

export function extractEmails(text) {
  const matches = text.match(EMAIL_RE);
  return matches ? [...new Set(matches.map((e) => e.toLowerCase()))] : [];
}

export function extractUrls(text) {
  const matches = text.match(URL_RE) || [];
  const cleaned = matches
    // The bare-domain branch also matches things like "file.txt" and the
    // domain half of an email address; drop both rather than reporting them
    // to the user as links.
    .filter((raw) => !/^[a-z0-9._%+-]+@/i.test(raw))
    .map((raw) => raw.replace(/[.,;:!?)]+$/, ""))
    .filter((raw) => raw.includes("."));
  return [...new Set(cleaned)];
}

export function extractPhones(text) {
  const matches = text.match(PHONE_RE) || [];
  return [...new Set(matches.map((p) => p.trim()).filter((p) => p.replace(/\D/g, "").length >= 8))];
}

// Leetspeak and symbol swaps. These are a scammer convention rather than a
// Unicode confusability class — Unicode agrees about "0" and "1" and says
// nothing about the rest — so they stay here, hand-maintained, instead of
// coming out of the generated table.
//
// NOTE: this is why a heuristic rule can never match `\d`. "8000" reaches a
// rule as "8ooo" and "24" as "2a". docs/PROGRESS.md says the same thing; the
// contract is load-bearing enough to be written down in both places.
const ASCII_SUBSTITUTIONS = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s",
};

const COMBINING_MARKS = /[̀-ͯ]/g;

/**
 * Fold a string toward plain ASCII Latin so it can be compared with something
 * written normally — a brand name, a keyword a rule looks for.
 *
 * The order matters. NFKD first, because it already unpacks the accented and
 * styled Latin (𝐩𝐚𝐲𝐩𝐚𝐥, 𝓅𝒶𝓎𝓅𝒶𝓁, and eleven more styles of it) that would
 * otherwise quadruple the table. Then the confusables, *before* lowercasing:
 * Unicode's twins are case-sensitive and folding them the other way round
 * loses that. Cyrillic В is identical to Latin B while в is not identical to
 * b, and only a case-sensitive fold can say so.
 */
export function foldConfusables(text) {
  return text
    .normalize("NFKD")
    .replace(CONFUSABLE_RE, (ch) => CONFUSABLES.get(ch) ?? ch)
    .replace(/[013457@$]/g, (ch) => ASCII_SUBSTITUTIONS[ch] ?? ch)
    .toLowerCase()
    .replace(COMBINING_MARKS, "");
}

// Normalize for matching: fold as above, then collapse whitespace, so the
// substitutions scammers use to dodge keyword filters ("v e r i f y",
// "acc0unt", "раyраl" with Cyrillic а/р) land on the plain spelling.
export function normalize(text) {
  return foldConfusables(text).replace(/\s+/g, " ").trim();
}

// Combining marks (Unicode categories Mn/Mc) from the ten primary Indic
// blocks. This must stay character-for-character identical to INDIC_MARKS in
// training/train_model.py — same ranges, same order, one line per script — so
// the two can be diffed by eye. tests/test_parity.py fails the build if they
// ever drift apart.
//
// They are written as escapes rather than literal characters because a
// combining mark standing alone in source has nothing to combine with, so
// editors render these as tofu or stack them onto the preceding backtick. A
// range nobody can read is a range nobody can review.
const INDIC_MARKS =
  String.raw`\u0900-\u0903\u093A-\u093C\u093E-\u094F\u0951-\u0957\u0962-\u0963` + // Devanagari
  String.raw`\u0981-\u0983\u09BC\u09BE-\u09C4\u09C7-\u09C8\u09CB-\u09CD\u09D7\u09E2-\u09E3\u09FE` + // Bengali
  String.raw`\u0A01-\u0A03\u0A3C\u0A3E-\u0A42\u0A47-\u0A48\u0A4B-\u0A4D\u0A51\u0A70-\u0A71\u0A75` + // Gurmukhi
  String.raw`\u0A81-\u0A83\u0ABC\u0ABE-\u0AC5\u0AC7-\u0AC9\u0ACB-\u0ACD\u0AE2-\u0AE3\u0AFA-\u0AFF` + // Gujarati
  String.raw`\u0B01-\u0B03\u0B3C\u0B3E-\u0B44\u0B47-\u0B48\u0B4B-\u0B4D\u0B55-\u0B57\u0B62-\u0B63` + // Oriya
  String.raw`\u0B82\u0BBE-\u0BC2\u0BC6-\u0BC8\u0BCA-\u0BCD\u0BD7` + // Tamil
  String.raw`\u0C00-\u0C04\u0C3C\u0C3E-\u0C44\u0C46-\u0C48\u0C4A-\u0C4D\u0C55-\u0C56\u0C62-\u0C63` + // Telugu
  String.raw`\u0C81-\u0C83\u0CBC\u0CBE-\u0CC4\u0CC6-\u0CC8\u0CCA-\u0CCD\u0CD5-\u0CD6\u0CE2-\u0CE3\u0CF3` + // Kannada
  String.raw`\u0D00-\u0D03\u0D3B-\u0D3C\u0D3E-\u0D44\u0D46-\u0D48\u0D4A-\u0D4D\u0D57\u0D62-\u0D63` + // Malayalam
  String.raw`\u0D81-\u0D83\u0DCA\u0DCF-\u0DD4\u0DD6\u0DD8-\u0DDF\u0DF2-\u0DF3`; // Sinhala

// Tokenizer that mirrors the `token_pattern` in training/train_model.py,
// r"(?u)\w[\w<INDIC_MARKS>]+", on lowercased input. The on-device model's
// weights are exported from sklearn, so this MUST stay in sync with training —
// tests/test_parity.py fails the build if the two ever diverge.
//
// `[\p{L}\p{N}_]` is how Python's `\w` is spelled in JavaScript, and that pair
// used to be the whole pattern. It excludes Unicode Marks, and Devanagari
// vowel signs are Marks, so "खाता" was four characters with no two word
// characters adjacent and tokenized to nothing at all — the model received an
// empty bag of terms for every Hindi-script message and voted on noise.
//
// The marks are added only as *continuation* characters. A mark can extend a
// token that already began on a letter but can never start one, which is why
// no character outside INDIC_MARKS changes behaviour: Latin text tokenizes
// exactly as it did before this class existed, and every weight the model
// learned on English is still the weight for the same term.
//
// \p{M} would have been shorter and is wrong twice over: it also matches the
// combining diacritics that decompose Latin text, which would silently change
// English tokenization, and it resolves against whichever Unicode version the
// engine happens to ship, which Python's `re` has no way to agree with.
const TOKEN_RE = new RegExp(String.raw`[\p{L}\p{N}_][\p{L}\p{N}_${INDIC_MARKS}]+`, "gu");

export function tokenize(text) {
  // String.prototype.match resets a global regex's lastIndex before it starts,
  // so sharing one compiled instance across calls is safe.
  return text.toLowerCase().match(TOKEN_RE) || [];
}

export function truncate(text, max = 60) {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? flat.slice(0, max) + "…" : flat;
}

// Shared by options.js and popup.js, both of which render a feed-sync
// timestamp — was two copies that could only ever drift apart, not two
// independent implementations.
export function relativeTime(epochMs) {
  const diffMin = Math.round((Date.now() - epochMs) / 60000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.round(diffHr / 24)}d ago`;
}
