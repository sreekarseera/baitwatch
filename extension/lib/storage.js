// All persistence. Nothing here leaves the user's machine.

const DEFAULT_SETTINGS = {
  autoScan: true,
  scanGmail: true,
  scanChat: true,
  scanGeneric: true,
  cloudTier: false, // requires apiKey; off until the user opts in
  apiKey: "",
  minSeverityToWarn: "suspicious", // "suspicious" | "dangerous"
  historyLimit: 500,
};

export async function getSettings() {
  const { settings = {} } = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...settings };
}

export async function saveSettings(partial) {
  const settings = { ...(await getSettings()), ...partial };
  await chrome.storage.local.set({ settings });
  return settings;
}

export { DEFAULT_SETTINGS };

/* ---------------------------------- history --------------------------------- */

export async function getHistory() {
  const { history = [] } = await chrome.storage.local.get("history");
  return history;
}

/**
 * Record one verdict. Deduplicates on (text, sender) so a re-scan of the same
 * open email doesn't fill the log — auto-scanning makes that the common case,
 * not the exception.
 */
export async function addHistoryEntry(entry) {
  const { historyLimit } = await getSettings();
  const history = await getHistory();

  const key = `${entry.text}|${entry.sender || ""}`;
  const existingIndex = history.findIndex((h) => `${h.text}|${h.sender || ""}` === key);
  if (existingIndex !== -1) {
    // Keep the newer verdict — the cloud tier may have upgraded it.
    history[existingIndex] = { ...history[existingIndex], ...entry };
  } else {
    history.push(entry);
  }

  const trimmed = history.slice(-historyLimit);
  await chrome.storage.local.set({ history: trimmed });
  return trimmed;
}

export async function clearHistory() {
  await chrome.storage.local.set({ history: [] });
}

/* --------------------------------- blocklist -------------------------------- */

export async function getBlocklist() {
  const { blocklist = [] } = await chrome.storage.local.get("blocklist");
  return blocklist;
}

export async function addBlocked(email) {
  const blocklist = await getBlocklist();
  const normalized = email.trim().toLowerCase();
  if (!normalized || blocklist.includes(normalized)) return blocklist;
  blocklist.push(normalized);
  await chrome.storage.local.set({ blocklist });
  return blocklist;
}

export async function removeBlocked(email) {
  const blocklist = await getBlocklist();
  const updated = blocklist.filter((e) => e !== email.trim().toLowerCase());
  await chrome.storage.local.set({ blocklist: updated });
  return updated;
}

/* --------------------------------- allowlist -------------------------------- */
// Senders the user has explicitly marked as fine. Without this, a false
// positive on a colleague's address re-fires on every single email they send,
// which is the fastest way to get a security tool uninstalled.

export async function getAllowlist() {
  const { allowlist = [] } = await chrome.storage.local.get("allowlist");
  return allowlist;
}

export async function addAllowed(email) {
  const allowlist = await getAllowlist();
  const normalized = email.trim().toLowerCase();
  if (!normalized || allowlist.includes(normalized)) return allowlist;
  allowlist.push(normalized);
  await chrome.storage.local.set({ allowlist });
  return allowlist;
}

export async function removeAllowed(email) {
  const allowlist = await getAllowlist();
  const updated = allowlist.filter((e) => e !== email.trim().toLowerCase());
  await chrome.storage.local.set({ allowlist: updated });
  return updated;
}

/* ----------------------------------- stats ---------------------------------- */

export async function bumpStat(name) {
  const { stats = {} } = await chrome.storage.local.get("stats");
  stats[name] = (stats[name] || 0) + 1;
  await chrome.storage.local.set({ stats });
}

export async function getStats() {
  const { stats = {} } = await chrome.storage.local.get("stats");
  return { scanned: 0, flagged: 0, cloudCalls: 0, ...stats };
}
