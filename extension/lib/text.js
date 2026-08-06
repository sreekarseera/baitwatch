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

// Tokenizer that mirrors scikit-learn's default `token_pattern` of
// r"(?u)\b\w\w+\b" on lowercased input. The on-device model's weights are
// exported from sklearn, so this MUST stay in sync with training —
// tests/test_parity.py fails the build if the two ever diverge.
export function tokenize(text) {
  return text.toLowerCase().match(/[\p{L}\p{N}_]{2,}/gu) || [];
}

export function truncate(text, max = 60) {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > max ? flat.slice(0, max) + "…" : flat;
}
