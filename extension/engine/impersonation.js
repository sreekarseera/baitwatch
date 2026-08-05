// Brand impersonation — does this page or message present itself as a brand it
// demonstrably isn't?
//
// The URL layer answers a narrower question: does the *domain* imitate a brand
// ("paypa1.com")? That misses the more common case, where the domain makes no
// attempt to look like anything — a page on `secure-portal-9f2.xyz` that puts
// PayPal's logo and wording in front of a password box. Nothing about the
// string "secure-portal-9f2.xyz" is suspicious on its own; the mismatch between
// what the page *claims to be* and where it is *served from* is the whole
// signal.
//
// Every rule here is conjunctive, and that is the point. A brand name in a page
// title proves nothing — news sites, review sites, and support forums say
// "Apple" and "Netflix" constantly. What almost never happens outside a
// credential harvest is a page naming a brand it doesn't belong to *while
// asking for that brand's password or one-time code*. Precision matters more
// than recall here: this layer scores high enough to move a verdict, so a rule
// that fires on ordinary browsing would be worse than no rule at all.

import { PROTECTED_BRANDS, registrableDomain, hostOf } from "./urls.js";

// Paths that mean "this link wants your credentials", not just "this link
// exists". Mirrors the set the URL layer uses.
const CREDENTIAL_PATH_RE = /\/(login|signin|sign-in|verify|secure|account|update|confirm|billing|kyc|otp)\b/i;

// The pretext language that precedes a credential request. Requiring it keeps
// the message-level rule off ordinary mail that merely names a brand — "we've
// moved to Google Workspace, sign in at intranet.example.com" is not a scam.
const PRETEXT_RE =
  /\b(?:verif(?:y|ication)|suspend(?:ed)?|lock(?:ed)?|deactivat(?:e|ed)|expir(?:e|ed|es|ing)|unusual\s*(?:activity|sign[\s-]?in)|unauthori[sz]ed|confirm\s*your|re-?activate|restore\s*(?:your\s*)?access|update\s*your\s*(?:details|information|payment))\b/i;

// "Sign in with Google" is a legitimate pattern on sites that have nothing to
// do with Google, and it appears next to a password field constantly. Stripping
// the whole phrase — brand token included — before matching removes an entire
// class of false positive for one regex.
// The trailing match is kept tight on purpose — "Sign in with your Apple ID
// and password" is *also* how a fake Apple page words itself, so this must
// swallow the button label and stop, not run on into the sentence around it.
const SSO_PHRASE_RE =
  /\b(?:sign[\s-]?in|log[\s-]?in|sign[\s-]?up|continue|register|connect|authenticate)\s+(?:with|using|via)\s+(?:your\s+)?[a-z]+(?:\s+(?:id|account|credentials))?/gi;

// A brand named in a footer, a cookie banner, or a list of "sites we support"
// is not the page presenting itself as that brand. Only the opening of the page
// counts as a claim of identity.
const LEAD_CHARS = 600;

// Naming a brand anywhere in the lead turned out to be far too loose — "Apple
// iCloud outage hits users worldwide" on a news site and "the Amazon Fire and
// Apple iPad" in a product review both matched, and both sites have a login
// box somewhere. What a page cannot do accidentally is put the brand in its
// *title*, or wire the brand directly to its sign-in prompt.
const SIGNIN_ADJACENT_RE =
  /(?:sign[\s-]?in|log[\s-]?in|login|signin|welcome)\s+(?:back\s+)?(?:to|into)\s+(?:your\s+)?$|^\s*(?:login|sign[\s-]?in|net\s?banking|internet\s+banking|account\s+login)/i;

// Credential-harvest pages are almost always thin: a logo, a form, a line of
// pretext. Articles, reviews and comparisons that merely mention a brand run to
// thousands of characters. This is the guard that separates the two.
const THIN_PAGE_CHARS = 2500;

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Word-boundary match that tolerates the punctuation and spacing brands get
// written with. Avoids \b so that aliases containing spaces or dots behave.
function mentions(haystack, alias) {
  return new RegExp(`(^|[^a-z0-9])${escapeRe(alias)}([^a-z0-9]|$)`, "i").test(haystack);
}

function isBrandDomain(domain, brand) {
  return brand.domains.includes(domain);
}

// The alias the text uses to claim this brand, or null.
function claimedAlias(brand, haystack) {
  for (const alias of brand.aliases || []) {
    if (mentions(haystack, alias)) return alias;
  }
  return null;
}

/**
 * Does this page present *itself* as the brand, as opposed to talking about it?
 *
 * Two ways to qualify: the brand is in the page title, or it sits directly
 * after the sign-in prompt ("Log in to your PayPal account", "SBI NetBanking").
 * A brand merely named somewhere in the body does not count.
 */
function claimsIdentity(brand, title, lead) {
  if (claimedAlias(brand, title)) return true;

  for (const alias of brand.aliases || []) {
    const at = lead.toLowerCase().indexOf(alias);
    if (at === -1) continue;
    const before = lead.slice(Math.max(0, at - 40), at);
    const after = lead.slice(at + alias.length, at + alias.length + 24);
    if (SIGNIN_ADJACENT_RE.test(before) || SIGNIN_ADJACENT_RE.test(after)) return true;
  }
  return false;
}

/**
 * Whole-page rule: the page says it is brand X, isn't served by brand X, and
 * wants a password or one-time code.
 */
function analyzePage(page, urlBrands) {
  const host = hostOf(page.url);
  if (!host) return [];

  const domain = registrableDomain(host);
  const credentials = page.credentialFields || [];
  // Without a credential field there is no harm to warn about and no way to
  // tell a phishing page from an article about the brand. This is the gate
  // that keeps the rule quiet during normal browsing.
  if (credentials.length === 0) return [];

  const body = page.text || "";
  // A page with an article's worth of text is an article. Whatever brand it
  // names, it is not a credential-harvest page pretending to be one.
  if (body.length > THIN_PAGE_CHARS) return [];

  const title = (page.title || "").replace(SSO_PHRASE_RE, " ");
  const lead = body.slice(0, LEAD_CHARS).replace(SSO_PHRASE_RE, " ");

  const signals = [];

  for (const brand of PROTECTED_BRANDS) {
    // The URL layer already convicted on this brand; don't bill twice.
    if (urlBrands.has(brand.name)) continue;
    if (isBrandDomain(domain, brand)) continue; // genuinely theirs
    if (!claimsIdentity(brand, title, lead)) continue;

    const asks = credentials.includes("password")
      ? credentials.includes("otp")
        ? "a password and a one-time code"
        : "a password"
      : "a one-time code";

    signals.push({
      id: "brand_impersonation",
      // Deliberately just under the score that convicts alone. A page like
      // this is nearly always a credential harvest, but "nearly always" should
      // still need one corroborating signal before the extension calls it
      // dangerous.
      weight: 2.6,
      detail: `This page presents itself as ${brand.name} and asks for ${asks}, but it is served from "${domain}" — not a ${brand.name} address (${brand.domains[0]}). Entering anything here sends it to whoever owns that domain.`,
      brand: brand.name,
    });

    // Only checked once a mismatch is established. On its own, a sign-in form
    // posting to another domain is normal — hosted auth providers do it all
    // day — so it earns its keep as corroboration, not as a rule of its own.
    const offsite = (page.formTargets || [])
      .map((action) => registrableDomain(hostOf(action) || ""))
      .find((target) => target && target !== domain);

    if (offsite) {
      signals.push({
        id: "offsite_credential_post",
        weight: 1.0,
        detail: `The sign-in form on this page sends what you type to "${offsite}", a different site from the one you are looking at.`,
      });
    }

    break; // one impersonated brand is the finding; listing more adds noise
  }

  return signals;
}

/**
 * Message rule: the text claims a brand, uses the pretext language that
 * precedes a credential request, and the link it wants you to follow goes
 * somewhere that isn't the brand.
 */
function analyzeMessage(text, urls, urlBrands) {
  if (!urls.length) return [];

  const cleaned = text.replace(SSO_PHRASE_RE, " ");
  if (!PRETEXT_RE.test(cleaned)) return [];

  for (const brand of PROTECTED_BRANDS) {
    if (urlBrands.has(brand.name)) continue;
    if (!claimedAlias(brand, cleaned)) continue;

    const foreign = urls.find((raw) => {
      if (!CREDENTIAL_PATH_RE.test(raw)) return false;
      const host = hostOf(raw);
      if (!host) return false;
      return !isBrandDomain(registrableDomain(host), brand);
    });
    if (!foreign) continue;

    return [
      {
        id: "brand_claim_mismatch",
        weight: 1.6,
        detail: `The message says it is from ${brand.name} and sends you to a sign-in page at "${hostOf(foreign)}". ${brand.name} uses ${brand.domains[0]}.`,
        brand: brand.name,
      },
    ];
  }

  return [];
}

/**
 * @param {string} text
 * @param {object} [opts]
 * @param {{url: string, title?: string, text?: string, credentialFields?: string[], formTargets?: string[]}} [opts.page]
 *   Present only for a whole-page scan. Its absence is what selects the
 *   message rule, which has no page address to compare against.
 * @param {string[]} [opts.urls] URLs the URL layer already extracted.
 * @param {Set<string>} [opts.urlBrands] Brands the URL layer flagged.
 * @returns {{score: number, signals: Array<{id, weight, detail}>}}
 */
export function analyzeImpersonation(text, opts = {}) {
  const urlBrands = opts.urlBrands || new Set();

  const signals = opts.page?.url
    ? analyzePage({ ...opts.page, text: opts.page.text ?? text }, urlBrands)
    : analyzeMessage(text, opts.urls || [], urlBrands);

  return {
    score: signals.reduce((sum, s) => sum + s.weight, 0),
    signals,
  };
}
