// Service worker — the only place analysis runs.
//
// Centralizing here means the ~260 KB model is parsed once per browser session
// rather than once per tab, detection logic never executes inside a page's
// origin, and the API key never has to be exposed to a content script.

import { analyze, VERDICT } from "../engine/engine.js";
import { createCloudAnalyzer } from "../engine/claude.js";
import {
  getSettings,
  addHistoryEntry,
  getBlocklist,
  getAllowlist,
  addBlocked,
  addAllowed,
  bumpStat,
} from "../lib/storage.js";

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

  const cloud =
    settings.cloudTier && settings.apiKey ? createCloudAnalyzer(settings.apiKey) : null;

  const result = await analyze(text, { sender: normalizedSender, source, cloud, extraUrls, page });

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
