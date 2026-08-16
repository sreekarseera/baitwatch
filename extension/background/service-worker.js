// Service worker — the only place analysis runs.
//
// Centralizing here means the ~260 KB model is parsed once per browser session
// rather than once per tab, detection logic never executes inside a page's
// origin, and the API key never has to be exposed to a content script.

import { analyze, VERDICT } from "../engine/engine.js";
import { createCloudAnalyzer } from "../engine/claude.js";
import { resolveShortenerLinks, SHORTENER_ORIGINS } from "../engine/shortener.js";
import { fetchUrlhausFeed, UrlhausAuthError, URLHAUS_ALARM } from "../engine/urlhaus.js";
import {
  getSettings,
  addHistoryEntry,
  getBlocklist,
  getAllowlist,
  addBlocked,
  addAllowed,
  bumpStat,
  getUrlhausFeed,
  saveUrlhausFeed,
} from "../lib/storage.js";

const URLHAUS_ORIGIN = "https://urlhaus.abuse.ch/*";

/**
 * Download the feed and replace the stored copy. Returns a result object
 * rather than throwing, since both the alarm handler and the options page's
 * manual refresh need to report a status without crashing the caller — a
 * failed refresh keeps whatever copy was already saved (see copy.md's "using
 * the copy from {relative time}" state).
 *
 * Deliberately does not gate on settings.checkUrlhaus: this same function
 * backs the options page's "Test" button, which has to work *before* the
 * toggle is switched on (mirrors testKey for the Claude tier, which has no
 * such gate either), and the toggle-on flow calls this before its own
 * saveSettings() write lands — gating here made both paths fail with
 * "checking is off" on every use that mattered. Whether a downloaded feed is
 * ever actually consulted is already decided correctly at read time, in
 * runAnalysis below (`settings.checkUrlhaus ? await getUrlhausFeed() : null`)
 * — downloading one early is inert, not a leak.
 */
async function refreshUrlhausFeed() {
  const settings = await getSettings();
  if (!(await chrome.permissions.contains({ origins: [URLHAUS_ORIGIN] }))) {
    return { ok: false, reason: "Permission to reach urlhaus.abuse.ch was revoked." };
  }
  try {
    const entries = await fetchUrlhausFeed(settings.urlhausAuthKey);
    const feed = await saveUrlhausFeed(entries);
    return { ok: true, feed };
  } catch (err) {
    return { ok: false, reason: err.message, authError: err instanceof UrlhausAuthError };
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === URLHAUS_ALARM) refreshUrlhausFeed();
});

const BADGE_COLORS = {
  [VERDICT.DANGEROUS]: "#b3261e",
  [VERDICT.SUSPICIOUS]: "#a2660a",
};

// Per-tab count of flagged messages, so the toolbar badge reflects the page
// the user is actually looking at.
const flaggedPerTab = new Map();

function updateBadge(tabId, verdict) {
  if (!tabId) return;
  const counts = flaggedPerTab.get(tabId) || { dangerous: 0, suspicious: 0 };
  if (verdict === VERDICT.DANGEROUS) counts.dangerous += 1;
  else if (verdict === VERDICT.SUSPICIOUS) counts.suspicious += 1;
  flaggedPerTab.set(tabId, counts);

  const total = counts.dangerous + counts.suspicious;
  if (!total) return;

  chrome.action.setBadgeText({ tabId, text: String(total) });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: counts.dangerous ? BADGE_COLORS[VERDICT.DANGEROUS] : BADGE_COLORS[VERDICT.SUSPICIOUS],
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    flaggedPerTab.delete(tabId);
    chrome.action.setBadgeText({ tabId, text: "" });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => flaggedPerTab.delete(tabId));

/**
 * Analyze one message, applying the user's block/allow lists first.
 */
async function runAnalysis({ text, sender = "", source = "manual", extraUrls = [], page = null }, tabId) {
  const settings = await getSettings();
  const normalizedSender = sender.trim().toLowerCase();

  // A sender the user has vouched for is skipped entirely. This is what keeps
  // one false positive from becoming a permanent recurring annoyance.
  if (normalizedSender) {
    const allowlist = await getAllowlist();
    if (allowlist.includes(normalizedSender)) {
      return { skipped: true, reason: "allowlisted", sender: normalizedSender };
    }
  }

  // A previously blocked sender is treated as dangerous without re-litigating
  // the text — the user already made this call.
  if (normalizedSender) {
    const blocklist = await getBlocklist();
    if (blocklist.includes(normalizedSender)) {
      const result = {
        verdict: VERDICT.DANGEROUS,
        score: 100,
        reasons: [{ id: "blocked_sender", detail: `You previously blocked ${normalizedSender}.` }],
        explanation: `This message is from ${normalizedSender}, which you have blocked.`,
        advice: "Do not reply, click anything, or send money. Delete it.",
        sender: normalizedSender,
        source,
        tier: "on-device",
        urls: [],
        analyzedAt: new Date().toISOString(),
      };
      updateBadge(tabId, result.verdict);
      return result;
    }
  }

  // Three things have to be true before a second opinion is even possible: the
  // tier is on, a key is saved, and the user has actually granted access to
  // api.anthropic.com. Checking the permission here rather than letting the
  // fetch fail keeps the verdict honest — an attempt that could never have
  // left the machine must not be reported as one that might have.
  const cloud =
    settings.cloudTier &&
    settings.apiKey &&
    (await chrome.permissions.contains({ origins: ["https://api.anthropic.com/*"] }))
      ? createCloudAnalyzer(settings.apiKey)
      : null;

  // Same pattern as the cloud tier: the setting alone is never enough to
  // attempt a request. A permission revoked from chrome://extensions must
  // fail closed, not throw a network error that reads like a bug.
  const resolveShortener =
    settings.resolveShorteners && (await chrome.permissions.contains({ origins: SHORTENER_ORIGINS }))
      ? resolveShortenerLinks
      : null;

  const urlhausFeed = settings.checkUrlhaus ? await getUrlhausFeed() : null;

  const result = await analyze(text, {
    sender: normalizedSender,
    source,
    cloud,
    extraUrls,
    page,
    resolveShortener,
    urlhausFeed,
  });

  await bumpStat("scanned");
  // Counts requests *attempted*, not answers received. Counting only successes
  // would mean the one statistic a user could audit their own privacy with
  // silently omitted every call that sent their text and then failed.
  if (result.tier === "claude" || result.tier === "cloud-failed") await bumpStat("cloudCalls");
  if (result.verdict !== VERDICT.SAFE) {
    await bumpStat("flagged");
    updateBadge(tabId, result.verdict);
  }

  await addHistoryEntry({
    // A whole-page scan can be 20 KB of text; storing that verbatim would
    // blow through the history budget in a handful of scans.
    text: source === "page" ? text.slice(0, 1000) : text,
    sender: normalizedSender,
    verdict: result.verdict,
    score: result.score,
    explanation: result.explanation || result.reasons[0]?.detail || "",
    reasons: result.reasons.map((r) => r.detail),
    tier: result.tier,
    source,
    timestamp: result.analyzedAt,
  });

  return result;
}

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  const tabId = sender.tab?.id;

  switch (msg.type) {
    case "ANALYZE":
      runAnalysis(msg, tabId)
        .then(respond)
        .catch((err) => respond({ error: err.message }));
      return true; // async

    case "GET_SETTINGS":
      getSettings().then(respond);
      return true;

    case "BLOCK_SENDER":
      addBlocked(msg.email).then(() => respond({ ok: true }));
      return true;

    case "ALLOW_SENDER":
      addAllowed(msg.email).then(() => respond({ ok: true }));
      return true;

    // Fired by options.js right after the toggle is switched on (so the user
    // doesn't wait up to an hour for the first copy) and by its "Test" button.
    // The recurring schedule itself is set up by options.js via
    // chrome.alarms.create/clear, since that's a plain extension-page API call
    // with nothing background-only about it.
    case "REFRESH_URLHAUS":
      refreshUrlhausFeed().then(respond);
      return true;

    default:
      return false;
  }
});

// Right-click any selected text -> scan it. This is the escape hatch for
// everything the adapters can't reach: canvas-rendered apps, PDFs in the
// viewer, text inside an iframe we don't have an adapter for.
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "baitwatch-scan-selection",
    title: "Check this text for scams",
    contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "baitwatch-scan-selection" || !info.selectionText) return;

  const result = await runAnalysis(
    { text: info.selectionText, source: "selection" },
    tab?.id
  );

  const label =
    result.verdict === VERDICT.DANGEROUS
      ? "⛔ Almost certainly a scam"
      : result.verdict === VERDICT.SUSPICIOUS
        ? "⚠️ Treat this with caution"
        : "✅ Nothing suspicious found";

  chrome.notifications.create({
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon128.png"),
    title: `${label} — risk ${result.score}/100`,
    message: result.explanation || result.reasons[0]?.detail || "No specific scam signals found.",
    priority: result.verdict === VERDICT.DANGEROUS ? 2 : 0,
  });
});
