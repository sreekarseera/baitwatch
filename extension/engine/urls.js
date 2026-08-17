// URL and domain reputation signals. Everything here is local — no lookups,
// no network. These are the signals that generalize best to scams the text
// classifier has never seen, because the delivery mechanism (a hostile link)
// changes far more slowly than the wording around it.

import { extractUrls, foldConfusables } from "../lib/text.js";
import { punycodeToUnicode } from "../lib/punycode.js";
import { PSL_RULES, PSL_WILDCARDS, PSL_EXCEPTIONS } from "./psl-data.js";

// Brands impersonated often enough to be worth checking for. `domains` lists
// the legitimate registrable domains — anything that *looks* like the brand but
// resolves elsewhere is the signal we care about.
//
// `aliases` are the names a page or message uses to present itself as the
// brand, for the impersonation check in impersonation.js. They are deliberately
// conservative: a generic word ("axis", "upi", "meta") matches ordinary writing
// far too often to be evidence of anything, so those brands are listed only
// under a qualified form.
//
// `domains` must list every domain the brand *actually signs users in on*, not
// just its marketing address. A domain missing here is worse than a brand
// missing entirely: the page says "Outlook", the domain isn't recognised as
// Microsoft's, and the real sign-in page gets called a credential harvest. That
// is what login.microsoftonline.com — where every Microsoft 365 and Azure AD
// login in the world lands — did before microsoftonline.com was added below.
export const PROTECTED_BRANDS = [
  { name: "PayPal", domains: ["paypal.com"], aliases: ["paypal", "pay pal"] },
  { name: "Amazon", domains: ["amazon.com", "amazon.in", "amazon.co.uk"], aliases: ["amazon"] },
  { name: "Apple", domains: ["apple.com", "icloud.com"], aliases: ["apple id", "icloud", "apple account"] },
  {
    name: "Microsoft",
    domains: [
      "microsoft.com",
      "live.com",
      "outlook.com",
      "office.com",
      "microsoftonline.com",
      "sharepoint.com",
      "skype.com",
      "azure.com",
    ],
    aliases: ["microsoft", "outlook", "office 365", "onedrive"],
  },
  {
    name: "Google",
    domains: ["google.com", "gmail.com", "youtube.com", "google.co.in", "googleusercontent.com"],
    aliases: ["google account", "gmail", "google drive"],
  },
  { name: "Netflix", domains: ["netflix.com"], aliases: ["netflix"] },
  { name: "Facebook", domains: ["facebook.com", "instagram.com", "whatsapp.com"], aliases: ["facebook", "instagram", "whatsapp"] },
  { name: "LinkedIn", domains: ["linkedin.com"], aliases: ["linkedin"] },
  { name: "FedEx", domains: ["fedex.com"], aliases: ["fedex"] },
  { name: "DHL", domains: ["dhl.com"], aliases: ["dhl"] },
  { name: "Chase", domains: ["chase.com"], aliases: ["chase bank", "jpmorgan chase"] },
  { name: "HDFC Bank", domains: ["hdfcbank.com"], aliases: ["hdfc", "hdfc bank", "netbanking hdfc"] },
  { name: "ICICI Bank", domains: ["icicibank.com"], aliases: ["icici", "icici bank"] },
  { name: "State Bank of India", domains: ["onlinesbi.sbi", "sbi.co.in"], aliases: ["state bank of india", "onlinesbi", "yono sbi", "sbi net banking"] },
  { name: "Axis Bank", domains: ["axisbank.com"], aliases: ["axis bank"] },
  { name: "NPCI / UPI", domains: ["npci.org.in"], aliases: ["npci", "bhim upi"] },
  { name: "Income Tax India", domains: ["incometax.gov.in"], aliases: ["income tax department", "incometax.gov.in"] },
];

// Also the set of origins `resolveShorteners` is allowed to contact — see
// manifest.json's optional_host_permissions, which must list the same
// domains by hand (Chrome requires them statically declared; there's no way
// to derive a manifest from this at build time without a build step). A test
// in tests/test_engine.mjs asserts the two lists match so they can't drift.
export const URL_SHORTENERS = new Set([
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

export // Whether any single label mixes Latin letters with letters from another
// alphabet. That — not punycode itself — is the attack: "рaypal" is a Cyrillic
// р wearing five Latin letters. A domain written wholly in Cyrillic, Han, or
// Devanagari is just a domain in that language, and treating all punycode as
// suspicious flagged every legitimate German, Russian, Chinese and Indian
// address. Checked per label, since "香港.com" mixing Han with a Latin TLD is
// completely normal.
const LATIN_LETTER = /\p{Script=Latin}/u;
const ANY_LETTER = /\p{L}/u;

function mixesScripts(decodedHost) {
  for (const label of decodedHost.split(".")) {
    let latin = false;
    let other = false;
    for (const ch of label) {
      if (!ANY_LETTER.test(ch)) continue;
      if (LATIN_LETTER.test(ch)) latin = true;
      else other = true;
      if (latin && other) return true;
    }
  }
  return false;
}

export function hostOf(rawUrl) {
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
  // Decode first. A non-Latin lookalike reaches us as "xn--aypal-uye.com",
  // and folding an ASCII envelope accomplishes nothing — the characters this
  // function exists to catch are only visible on the other side of the decode.
  //
  // The fold itself is the shared one in lib/text.js, backed by the full
  // Unicode confusables table. This used to be a second hand-picked map that
  // had drifted out of step with the one in text.js, and both of them stopped
  // at the letters someone had thought to list: an attacker only had to reach
  // for Greek sigma or Cyrillic omega to walk past both.
  return foldConfusables(punycodeToUnicode(domain))
    // "rn" renders almost identically to "m" at normal size — "arnazon.com"
    // is a real and frequently-used registration. Folding it here rather than
    // leaning on edit distance matters because it costs two edits, which puts
    // it outside the tolerance short brand names are allowed.
    .replace(/rn/g, "m")
    // Anything that survived the fold is a character with no Latin reading at
    // all. Dropping it is what keeps a wholly non-Latin domain from being
    // compared against a brand on the strength of two coincidental letters.
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

      // Folds to the brand's domain exactly, but isn't it: "paypa1.com",
      // "рaypal.com" (Cyrillic р), "arnazon.com". This has to be checked
      // before the edit-distance branch below, which compares the *folded*
      // labels and therefore sees these as identical — meaning its
      // `domainLabel !== legitLabel` guard skipped them and the most
      // clear-cut impersonation of all fell through unflagged.
      if (domainSkeleton === skeleton(legit)) {
        return { brand: brand.name, legit, kind: "homoglyph" };
      }

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
      // What the user actually sees. Telling someone that "xn--aypal-uye.com"
      // imitates PayPal explains nothing — the whole attack is that it renders
      // as "рaypal.com", so that is what the warning has to lead with.
      const shown = punycodeToUnicode(host);
      const LOOKALIKE_DETAIL = {
        homoglyph:
          shown === host
            ? `"${host}" is built from characters chosen to read as ${lookalike.brand}'s real domain (${lookalike.legit}) — it is a different site owned by someone else.`
            : `"${shown}" is spelled with non-Latin characters chosen to read as ${lookalike.brand}'s real domain (${lookalike.legit}). The address is really "${host}" — a different site owned by someone else.`,
        typo: `"${host}" is one or two characters away from ${lookalike.brand}'s real domain (${lookalike.legit}).`,
        subdomain: `"${host}" puts ${lookalike.brand}'s name in a subdomain of an unrelated site — the real domain is ${lookalike.legit}.`,
        compound: `"${host}" bolts a reassuring word onto ${lookalike.brand}'s name. ${lookalike.brand} only uses ${lookalike.legit}.`,
      };
      signals.push({
        id: "lookalike_domain",
        weight: 3.0,
        detail: LOOKALIKE_DETAIL[lookalike.kind],
        // Carried so the impersonation layer doesn't charge for the same
        // brand twice — "this domain imitates PayPal" and "this page claims
        // to be PayPal" are one finding, not two.
        brand: lookalike.brand,
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

    // Only worth saying on its own. Once a lookalike has been identified the
    // warning already names the brand being imitated, which is the same fact
    // told better.
    if (!lookalike && (host.startsWith("xn--") || host.includes(".xn--"))) {
      const shown = punycodeToUnicode(host);
      const mixed = mixesScripts(shown);
      signals.push({
        id: mixed ? "mixed_script_host" : "punycode_host",
        weight: mixed ? 1.6 : 0.5,
        detail: mixed
          ? `"${shown}" mixes alphabets — some of those letters are not the Latin ones they look like. Its actual address is "${host}".`
          : `"${shown}" is an internationalized domain written in a non-Latin alphabet. Its actual address is "${host}".`,
      });
    }

    // Credential-harvest paths on a domain that isn't the brand it names.
    //
    // The "isn't the brand it names" half was in this comment but never in the
    // code: only lookalikes were excluded, so a bank's own sign-in URL scored
    // here too. Every real login page on the internet has /login in its path —
    // infinity.icicibank.com/corp/Login.jsp is the genuine ICICI one — and the
    // path is only evidence of anything when the domain is not itself known
    // good.
    const onKnownBrand = PROTECTED_BRANDS.some((brand) => brand.domains.includes(registrableDomain(host)));
    if (
      /\/(login|signin|verify|secure|account|update|confirm|billing|kyc|otp)\b/i.test(raw) &&
      !lookalike &&
      !onKnownBrand
    ) {
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
