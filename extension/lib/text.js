// Text utilities shared by the engine, content scripts, and popup.
// Kept dependency-free so content scripts can use the same code as the popup.

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

// Normalize for matching: lowercase, collapse whitespace, and fold the
// homoglyph/leetspeak substitutions scammers use to dodge keyword filters
// ("v e r i f y", "acc0unt", "раyраl" with Cyrillic а/р).
const HOMOGLYPHS = {
  а: "a", е: "e", о: "o", р: "p", с: "c", х: "x", у: "y", і: "i", ѕ: "s",
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", $: "s",
};

export function normalize(text) {
  return text
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[аеорсхуіѕ0134573@$]/g, (ch) => HOMOGLYPHS[ch] ?? ch)
    .replace(/\s+/g, " ")
    .trim();
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
