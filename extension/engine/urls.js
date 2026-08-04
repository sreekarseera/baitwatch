// URL and domain reputation signals. Everything here is local — no lookups,
// no network. These are the signals that generalize best to scams the text
// classifier has never seen, because the delivery mechanism (a hostile link)
// changes far more slowly than the wording around it.

import { extractUrls } from "../lib/text.js";
import { PSL_RULES, PSL_WILDCARDS, PSL_EXCEPTIONS } from "./psl-data.js";

// Brands impersonated often enough to be worth lookalike-checking. Each entry
// is the legitimate registrable domain; anything that *looks* like the brand
// but resolves elsewhere is the signal we care about.
const PROTECTED_BRANDS = [
  { name: "PayPal", domains: ["paypal.com"] },
  { name: "Amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk"] },
  { name: "Apple", domains: ["apple.com", "icloud.com"] },
  { name: "Microsoft", domains: ["microsoft.com", "live.com", "outlook.com", "office.com"] },
  { name: "Google", domains: ["google.com", "gmail.com", "youtube.com"] },
  { name: "Netflix", domains: ["netflix.com"] },
  { name: "Facebook", domains: ["facebook.com", "instagram.com", "whatsapp.com"] },
  { name: "LinkedIn", domains: ["linkedin.com"] },
  { name: "FedEx", domains: ["fedex.com"] },
  { name: "DHL", domains: ["dhl.com"] },
  { name: "Chase", domains: ["chase.com"] },
  { name: "HDFC Bank", domains: ["hdfcbank.com"] },
  { name: "ICICI Bank", domains: ["icicibank.com"] },
  { name: "State Bank of India", domains: ["onlinesbi.sbi", "sbi.co.in"] },
  { name: "Axis Bank", domains: ["axisbank.com"] },
  { name: "NPCI / UPI", domains: ["npci.org.in"] },
  { name: "Income Tax India", domains: ["incometax.gov.in"] },
];

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
  "t.ly", "snip.ly", "s.id", "clck.ru", "u.to", "v.gd",
]);

// TLDs with cheap/anonymous registration and disproportionate abuse rates.
const HIGH_RISK_TLDS = new Set([
  "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "click",
  "link", "work", "loan", "download", "review", "country", "kim", "men",
  "rest", "cam", "quest", "cfd", "sbs", "lol",
]);

// Public suffix lookup, backed by the full Mozilla list in psl-data.js.
//
// This used to be a hand-picked set of ~20 suffixes, which was wrong in a way
// that mattered: it had no entry for hosting platforms, so `evil.github.io`
// and `legit.github.io` both reduced to `github.io`. Free hosting is where a
// large share of phishing pages actually live, and treating every page on a
// platform as one domain made them indistinguishable — including from the
// platform's own legitimate pages.
//
// Returns the public suffix for a hostname, or null if none matches (in which
// case the caller falls back to the default "*" rule from the spec).
function publicSuffix(host) {
  const labels = host.split(".");

  // Exceptions win outright: `!city.kawasaki.jp` carves that name back out of
  // the `*.kawasaki.jp` wildcard, making the suffix one label shorter.
  for (let i = 0; i < labels.length; i += 1) {
    if (PSL_EXCEPTIONS.has(labels.slice(i).join("."))) {
      return labels.slice(i + 1).join(".");
    }
  }

  // Otherwise the longest matching rule wins. Walking left to right tries the
  // longest candidate first, so the first hit is the answer.
  for (let i = 0; i < labels.length; i += 1) {
    const candidate = labels.slice(i).join(".");
    if (PSL_RULES.has(candidate)) return candidate;
    // A `*.foo` rule makes any single label under `foo` a suffix itself.
    if (i + 1 < labels.length && PSL_WILDCARDS.has(labels.slice(i + 1).join("."))) {
      return candidate;
    }
  }

  return null;
}

function hostOf(rawUrl) {
  const withScheme = /^https?:\/\//i.test(rawUrl) ? rawUrl : `http://${rawUrl}`;
  try {
    return new URL(withScheme).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

export function registrableDomain(host) {
  if (!host) return host;

  const suffix = publicSuffix(host);

  // No rule matched. The spec's default is "*", meaning the last label is the
  // suffix — so the registrable domain is the last two labels, which is what
  // the old hand-rolled version always did.
  if (suffix === null) {
    const parts = host.split(".");
    return parts.length <= 2 ? host : parts.slice(-2).join(".");
  }

  // The hostname *is* a public suffix (`github.io`, `co.uk`). Nobody registered
  // it, so there is no registrable domain below it — hand back the host itself
  // rather than inventing one.
  if (suffix === host) return host;

  const suffixLabels = suffix ? suffix.split(".").length : 0;
  return host.split(".").slice(-(suffixLabels + 1)).join(".");
}

// Levenshtein with an early bail-out: we only ever ask "is this within 2
// edits", so there's no reason to fill the whole matrix for long strings.
export function editDistance(a, b, maxDistance = Infinity) {
  if (Math.abs(a.length - b.length) > maxDistance) return maxDistance + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const curr = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      curr[j] = Math.min(
        prev[j] + 1,
        curr[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
      rowMin = Math.min(rowMin, curr[j]);
    }
    if (rowMin > maxDistance) return maxDistance + 1;
    prev = curr;
  }
  return prev[b.length];
}

// Fold the characters commonly swapped to build a visually-identical domain,
// so "paypa1.com", "pay-pal.com" and "рaypal.com" all resolve toward "paypal".
// Hyphens are deliberately preserved: they're the separator in the
// "brand-plus-word" pattern below, and dropping them would erase the seam.
function skeleton(domain) {
  return domain
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[аеорсхуіѕ]/g, (ch) => ({ а: "a", е: "e", о: "o", р: "p", с: "c", х: "x", у: "y", і: "i", ѕ: "s" }[ch]))
    .replace(/[01345]/g, (ch) => ({ "0": "o", "1": "l", "3": "e", "4": "a", "5": "s" }[ch]))
    .replace(/[^a-z.-]/g, "");
}

function lookalikeMatch(host) {
  const domain = registrableDomain(host);
  const domainSkeleton = skeleton(domain);
  const [domainLabel] = domainSkeleton.split(".");

  for (const brand of PROTECTED_BRANDS) {
    for (const legit of brand.domains) {
      if (domain === legit || host === legit || host.endsWith(`.${legit}`)) return null; // genuine
      const legitLabel = skeleton(legit).split(".")[0];

      // Same brand name, different registrable domain: "paypal.security-check.tk".
      if (domainSkeleton !== skeleton(legit) && host.split(".").slice(0, -2).some((sub) => skeleton(sub) === legitLabel)) {
        return { brand: brand.name, legit, kind: "subdomain" };
      }

      // Brand plus a reassuring word: "paypal-secure.com", "amazon-verify.net".
      // Splitting on the hyphen is what keeps this from firing on legitimate
      // names that merely contain a brand as a substring ("applebees.com"),
      // which a naive `includes()` would flag constantly.
      const parts = domainLabel.split("-");
      if (parts.length > 1 && parts.includes(legitLabel)) {
        return { brand: brand.name, legit, kind: "compound" };
      }

      // Typo/homoglyph of the brand label: "paypa1.com", "arnazon.com".
      if (domainLabel !== legitLabel && domainLabel.length >= 4) {
        const distance = editDistance(domainLabel, legitLabel, 2);
        if (distance <= (legitLabel.length > 8 ? 2 : 1)) {
          return { brand: brand.name, legit, kind: "typo" };
        }
      }
    }
  }
  return null;
}

/**
 * Score every URL in a block of text.
 *
 * @param {string} text
 * @param {string[]} [extraUrls] URLs discovered outside the text — link
 *   `href` attributes and the page's own address during a whole-page scan.
 *   These matter more than anything in the visible text: a phishing page
 *   shows "Sign in" and hides the hostile domain in the href, so a
 *   text-only extraction misses the one signal that counts.
 * @returns {{score: number, signals: Array<{id, weight, detail}>, urls: string[]}}
 *   score is an unbounded positive risk contribution; the engine normalizes it.
 */
export function analyzeUrls(text, extraUrls = []) {
  const urls = [...new Set([...extractUrls(text), ...extraUrls])];
  const signals = [];

  for (const raw of urls) {
    const host = hostOf(raw);
    if (!host) continue;
    const domain = registrableDomain(host);
    const tld = domain.split(".").pop();

    const lookalike = lookalikeMatch(host);
    if (lookalike) {
      const LOOKALIKE_DETAIL = {
        typo: `"${host}" is one or two characters away from ${lookalike.brand}'s real domain (${lookalike.legit}).`,
        subdomain: `"${host}" puts ${lookalike.brand}'s name in a subdomain of an unrelated site — the real domain is ${lookalike.legit}.`,
        compound: `"${host}" bolts a reassuring word onto ${lookalike.brand}'s name. ${lookalike.brand} only uses ${lookalike.legit}.`,
      };
      signals.push({
        id: "lookalike_domain",
        weight: 3.0,
        detail: LOOKALIKE_DETAIL[lookalike.kind],
      });
    }

    if (URL_SHORTENERS.has(domain)) {
      signals.push({
        id: "url_shortener",
        weight: 1.1,
        detail: `"${host}" is a link shortener, which hides where the link actually goes.`,
      });
    }

    if (HIGH_RISK_TLDS.has(tld)) {
      signals.push({
        id: "high_risk_tld",
        weight: 1.0,
        detail: `".${tld}" is a domain ending with very high abuse rates and near-anonymous registration.`,
      });
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      signals.push({
        id: "ip_address_host",
        weight: 1.8,
        detail: `The link points at a raw IP address (${host}) instead of a domain name.`,
      });
    }

    if (host.startsWith("xn--") || host.includes(".xn--")) {
      signals.push({
        id: "punycode_host",
        weight: 1.6,
        detail: `"${host}" is a punycode domain — it renders as non-Latin characters that can imitate a real brand.`,
      });
    }

    // Credential-harvest paths on a domain that isn't the brand it names.
    if (/\/(login|signin|verify|secure|account|update|confirm|billing|kyc|otp)\b/i.test(raw) && !lookalike) {
      signals.push({
        id: "credential_path",
        weight: 0.6,
        detail: `"${host}" links straight to a login/verification page.`,
      });
    }

    if (host.split(".").length >= 5) {
      signals.push({
        id: "deep_subdomain",
        weight: 0.7,
        detail: `"${host}" buries the real domain under ${host.split(".").length - 2} subdomains.`,
      });
    }

    // "https://apple.com@evil.tk" — everything before the @ is a username.
    if (/^https?:\/\/[^/\s]*@/i.test(raw)) {
      signals.push({
        id: "userinfo_url",
        weight: 2.4,
        detail: `The link uses an "@" trick so it appears to point at one site while actually loading ${host}.`,
      });
    }
  }

  // Deduplicate identical signals so five shortener links don't score 5×.
  const seen = new Set();
  const unique = signals.filter((s) => {
    const key = `${s.id}|${s.detail}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    score: unique.reduce((sum, s) => sum + s.weight, 0),
    signals: unique,
    urls,
  };
}
