// Shortener resolution — first hop only.
//
// See docs/design/network-consent/rationale.md ("Question 1") for why first-
// hop-only is the only option the optional_host_permissions model supports at
// all, not a UX compromise: the set of origins a permission grant can ever
// cover has to be declared in the manifest in advance, so only the shortener
// domain itself (the first hop) can be pre-declared. Where a redirect chain
// goes after that is decided by whatever the first server returns and can't
// be known ahead of time.
//
// Implementation note: `fetch(url, { redirect: "manual" })` deliberately
// cannot be used to read the destination. Its Response is filtered to type
// "opaqueredirect" by the platform — headers, including Location, are
// inaccessible even with host permission for the origin, because the
// filtering happens before extension code ever sees the response. The
// request still reaches the network and the redirect still happens at the
// transport layer regardless of fetch's redirect mode, so
// chrome.webRequest.onBeforeRedirect (which observes the wire, not the
// Response object) is what actually exposes `redirectUrl`. This needs the
// unconditional "webRequest" entry in manifest.json's base `permissions` —
// that alone grants no network access; it only lets the extension observe
// requests to origins it already separately holds a host permission for.

import { URL_SHORTENERS, hostOf } from "./urls.js";

// The optional_host_permissions request/removal target for resolveShorteners
// — one array, requested and released as a single grant, the same way
// options.js already treats ANTHROPIC_ORIGIN for the Claude tier. Manifest.json
// must list these same 19 origins statically (see the comment on
// URL_SHORTENERS in urls.js for why that can't be generated at build time);
// tests/test_engine.mjs asserts the two lists match.
export const SHORTENER_ORIGINS = [...URL_SHORTENERS].map((domain) => `https://${domain}/*`);

// extractUrls() (lib/text.js) matches bare domains like "bit.ly/xyz" as well
// as scheme-prefixed ones, since that's how these links routinely appear in
// SMS and chat text. `new URL()` throws on the bare form, which a naive
// isShortenerUrl silently swallowed via try/catch — recognizing nothing.
// hostOf() already exists in urls.js to solve exactly this (it prepends a
// scheme before parsing), so this reuses it instead of a second copy of the
// same fix.
export function isShortenerUrl(url) {
  const host = hostOf(url);
  return host ? URL_SHORTENERS.has(host) : false;
}

// Also fixes a narrower gap: manifest.json only declares https:// origins for
// shorteners (every shortener in the list serves https), so an explicit
// http:// link in the source text — or a bare domain, which fetch() cannot
// resolve as a relative URL inside a service worker at all — has no matching
// host permission and fails silently. Normalizing here means resolveFirstHop
// always fetches the same https origin that was actually granted.
function normalizeToHttps(url) {
  return `https://${url.replace(/^https?:\/\//i, "")}`;
}

/**
 * Resolve one shortener link's first redirect hop.
 * @param {string} url
 * @param {{timeoutMs?: number}} [opts]
 * @returns {Promise<string|null>} the redirect target, or null if the request
 *   didn't redirect (dead link, 404, etc.) or timed out.
 */
export function resolveFirstHop(url, { timeoutMs = 6000 } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      chrome.webRequest.onBeforeRedirect.removeListener(onRedirect);
      clearTimeout(timer);
      resolve(result);
    };

    const onRedirect = (details) => {
      if (details.url !== url) return;
      finish(details.redirectUrl || null);
    };

    chrome.webRequest.onBeforeRedirect.addListener(onRedirect, { urls: [url] });
    const timer = setTimeout(() => finish(null), timeoutMs);

    // Fired to make the request happen at all; its Response is unusable by
    // design (see module note above) and is deliberately ignored here — the
    // answer comes from the webRequest listener, not this call's return value.
    fetch(url, { method: "HEAD", redirect: "manual" }).catch(() => finish(null));
  });
}

/**
 * Resolve every shortener link in a URL list, first hop only, stopping at one
 * hop even when the destination is itself a recognized shortener (chained
 * shorteners are only unwound once — see rationale.md).
 * @param {string[]} urls
 * @returns {Promise<{resolved: boolean, destinations: Map<string,string>}>}
 */
export async function resolveShortenerLinks(urls) {
  const targets = [...new Set(urls.map(normalizeToHttps))].filter(isShortenerUrl);
  if (!targets.length) return { resolved: false, destinations: new Map() };

  const destinations = new Map();
  await Promise.all(
    targets.map(async (url) => {
      const dest = await resolveFirstHop(url);
      if (dest) destinations.set(url, dest);
    })
  );

  return { resolved: destinations.size > 0, destinations };
}
