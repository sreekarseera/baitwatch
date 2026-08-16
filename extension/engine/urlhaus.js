// URLhaus feed check — a downloaded list, matched locally, never a per-link
// query. See docs/design/network-consent/rationale.md ("Question 2") for why:
// URLhaus's live lookup API has no hash-based endpoint for URLs (only for
// malware-sample hashes, a different object), so a live per-URL query was
// never the better design regardless of authentication. Downloading their
// standard feed on a timer and matching against the local copy sends
// strictly less: not even an indication that a check is happening.
//
// VERIFIED END TO END 2026-08-16 — this needed correcting, not just
// flagging, and then needed a second round of correction after the first
// "verified" turned out to be premature.
//
// Path and auth: rationale.md assumed (reasonably, from abuse.ch's mid-2025
// "Auth-Key mandatory on every API call" announcement) that the feed
// download would need one too, and couldn't confirm it because their
// downloads page 403s an automated fetch without a browser User-Agent. With
// one, it doesn't 403: `curl` against
// `https://urlhaus.abuse.ch/downloads/csv_recent/` returns 200 with the live
// feed, no key, consistently. Two other guessed paths
// (`v2/urls/exports/{key}/recent.csv`, `v2/urls/recent/`) both 404 — wrong
// resource, not wrong key, which is how this was caught rather than shipped:
// a 404 doesn't need a real key to observe. A third guess,
// `v2/files/exports/{key}/recent.csv`, 401s (exists, wants auth) — the
// malware-*sample* export this file's other comments already say is a
// different resource from the URL list.
//
// Reachability from the extension is a separate axis from the path, and the
// first pass here conflated them. A same-day follow-up test — actually
// calling fetchUrlhausFeed() from a loaded extension via CDP, not just
// curl-ing the URL — got HTTP 405 "Banned" from Fastly's edge (the response
// body literally says so), on both the extension's fetch() and a bare
// top-level Page.navigate() to the same URL with no extension involved.
// Isolated to headless Chrome specifically: a windowed (non-headless) Chrome
// for Testing instance, extension loaded, calling the real REFRESH_URLHAUS
// message handler, got a clean 200 and landed 16,930 real entries in
// chrome.storage.local — full pipeline, fetch through parseFeed through
// storage, no code changes. Headless automation is a well-known bot-defense
// fingerprint target; this is a property of *how this was tested*
// (`run_all.py`'s browser layer runs headless), not of the shipped code, but
// it means CI-style headless testing of this one feature will reliably see
// a false failure and should not be read as a regression if it recurs.
//
// An Auth-Key is still accepted and sent when the user has one, for the day
// abuse.ch does bring this endpoint under the mandate — but it is not
// required to enable the feature, and the UI must not claim otherwise.

import { extractUrls } from "../lib/text.js";

export const URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/";

// Shared between background/service-worker.js (the alarm listener) and
// options/options.js (which schedules/cancels the alarm — a plain
// chrome.alarms call needs nothing background-only about it). Defined once
// here, rather than in service-worker.js, so options.js can import it without
// also pulling in and re-running the service worker's top-level listener
// registrations.
export const URLHAUS_ALARM = "urlhaus-refresh";
export const URLHAUS_REFRESH_MINUTES = 60;

class UrlhausAuthError extends Error {}

/**
 * Download the feed and return a flat list of malicious URLs. Throws on any
 * failure — the caller (background/service-worker.js) is responsible for
 * keeping the last-good copy when a refresh fails, per copy.md's sync-status
 * strings.
 * @param {string} [authKey] optional — not required by the verified endpoint
 *   today, but sent when present in case that changes.
 * @returns {Promise<string[]>}
 */
export async function fetchUrlhausFeed(authKey) {
  const response = await fetch(URLHAUS_FEED_URL, authKey ? { headers: { "Auth-Key": authKey } } : undefined);

  if (response.status === 401 || response.status === 403) {
    throw new UrlhausAuthError(
      authKey
        ? "abuse.ch rejected this Auth-Key. Check that you copied it correctly from auth.abuse.ch."
        : "abuse.ch now requires an Auth-Key for this feed. Add one in Settings."
    );
  }
  if (!response.ok) {
    throw new Error(`abuse.ch returned an error (${response.status}).`);
  }

  const body = await response.text();
  return parseFeed(body);
}

/**
 * Extract one URL per non-comment line, tolerant of either a bare URL list or
 * a CSV export with a URL column — see module note above.
 * @param {string} body
 * @returns {string[]}
 */
export function parseFeed(body) {
  const urls = [];
  for (const line of body.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const [first] = extractUrls(trimmed);
    if (first) urls.push(normalizeForMatch(first));
  }
  return [...new Set(urls)];
}

function normalizeForMatch(url) {
  return url.replace(/\/+$/, "");
}

/**
 * @param {string[]} candidateUrls URLs pulled from the message under review
 * @param {{entries: string[]}|null} feed
 * @returns {string|null} the first candidate that matched, or null
 */
export function matchUrlhaus(candidateUrls, feed) {
  if (!feed?.entries?.length) return null;
  const known = new Set(feed.entries);
  return candidateUrls.map(normalizeForMatch).find((url) => known.has(url)) || null;
}

export { UrlhausAuthError };
