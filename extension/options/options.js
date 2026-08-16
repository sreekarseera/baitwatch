import { getSettings, saveSettings, getUrlhausFeed, clearUrlhausFeed } from "../lib/storage.js";
import { relativeTime } from "../lib/text.js";
import { looksLikeApiKey, verifyApiKey } from "../engine/claude.js";
import { modelInfo } from "../engine/model.js";
import { SHORTENER_ORIGINS } from "../engine/shortener.js";
import { URLHAUS_ALARM, URLHAUS_REFRESH_MINUTES } from "../engine/urlhaus.js";

const $ = (id) => document.getElementById(id);

const TOGGLES = ["autoScan", "scanGmail", "scanChat", "scanGeneric", "cloudTier", "resolveShorteners", "checkUrlhaus"];

let savedTimer = null;
function flashSaved() {
  const el = $("saved");
  el.hidden = false;
  clearTimeout(savedTimer);
  savedTimer = setTimeout(() => (el.hidden = true), 1400);
}

function setStatus(elId, message, kind) {
  const el = $(elId);
  el.hidden = !message;
  el.textContent = message;
  el.className = `status ${kind || ""}`;
}
const setKeyStatus = (message, kind) => setStatus("keyStatus", message, kind);
const setShortenerStatus = (message, kind) => setStatus("shortenerStatus", message, kind);
const setUrlhausKeyStatus = (message, kind) => setStatus("urlhausKeyStatus", message, kind);

function syncDependentState() {
  document.querySelector(".indent").classList.toggle("disabled", !$("autoScan").checked);
}

/* --------------------------- network permission --------------------------- */
// Each of the three network features below is an optional host permission,
// not one granted at install. The extension's central claim is that nothing
// leaves your machine by default; a permission every user must grant on
// install for a feature that is off by default contradicts that at exactly
// the moment they are deciding whether to trust it. Requesting a feature's
// origins only when its own toggle is switched on makes each grant mean what
// it says — and revoking on toggle-off means turning a feature off actually
// takes the ability away rather than just setting a flag. See rationale.md
// for why this stays three independent grants instead of one.
//
// Chrome only honours permissions.request() during a user gesture, which is
// why every call below hangs off a click or a change event.

const ANTHROPIC_ORIGINS = ["https://api.anthropic.com/*"];
const URLHAUS_ORIGINS = ["https://urlhaus.abuse.ch/*"];

function hasPermission(origins) {
  return chrome.permissions.contains({ origins });
}

async function requestPermission(origins) {
  if (await hasPermission(origins)) return true;
  try {
    return await chrome.permissions.request({ origins });
  } catch {
    // Thrown when there is no user gesture to attach to.
    return false;
  }
}

/* ---------------------------------- load ---------------------------------- */

const settings = await getSettings();

TOGGLES.forEach((id) => ($(id).checked = Boolean(settings[id])));
$("minSeverityToWarn").value = settings.minSeverityToWarn;
$("apiKey").value = settings.apiKey || "";
$("urlhausAuthKey").value = settings.urlhausAuthKey || "";
syncDependentState();

if (settings.cloudTier && !settings.apiKey) {
  setKeyStatus("The second opinion is on but no API key is saved, so it can't run.", "err");
} else if (settings.cloudTier && !(await hasPermission(ANTHROPIC_ORIGINS))) {
  // Chrome lets a user revoke host access from chrome://extensions without
  // telling the extension. The setting would still read "on" and every scan
  // would fail one at a time; say it once, here, instead.
  setKeyStatus(
    "Permission to reach api.anthropic.com was revoked, so the second opinion " +
      "cannot run. Switch it off and on again to restore it.",
    "err"
  );
}

if (settings.resolveShorteners && !(await hasPermission(SHORTENER_ORIGINS))) {
  setShortenerStatus(
    "Permission to reach shortening services was revoked, so this can't run. " +
      "Switch it off and on again to restore it.",
    "err"
  );
}

if (settings.checkUrlhaus && !(await hasPermission(URLHAUS_ORIGINS))) {
  setUrlhausKeyStatus(
    "Permission to reach urlhaus.abuse.ch was revoked, so this can't run. " +
      "Switch it off and on again to restore it.",
    "err"
  );
}

async function renderUrlhausSyncStatus() {
  const feed = await getUrlhausFeed();
  const el = $("urlhausSyncStatus");
  if (!feed) {
    el.textContent = "Not yet downloaded.";
    return;
  }
  el.textContent = `List last updated ${relativeTime(feed.updatedAt)} — ${feed.entries.length.toLocaleString()} entries.`;
}
await renderUrlhausSyncStatus();

/* --------------------------------- persist -------------------------------- */

TOGGLES.forEach((id) =>
  $(id).addEventListener("change", async () => {
    if (id === "cloudTier" && $(id).checked) {
      // Ask for network access at the moment the feature is switched on. A
      // refusal has to switch the toggle back: leaving it on would promise a
      // second opinion the extension has no way to fetch.
      if (!(await requestPermission(ANTHROPIC_ORIGINS))) {
        $(id).checked = false;
        await saveSettings({ cloudTier: false });
        setKeyStatus(
          "The second opinion needs permission to reach api.anthropic.com. " +
            "Without it nothing can be sent, so the feature stays off.",
          "err"
        );
        return;
      }
      // Turning on the cloud tier without a key would silently do nothing;
      // say so rather than letting the user think it's working.
      if (!$("apiKey").value.trim()) {
        setKeyStatus("Add your Anthropic API key below to enable this.", "err");
      }
    }

    if (id === "resolveShorteners" && $(id).checked) {
      if (!(await requestPermission(SHORTENER_ORIGINS))) {
        $(id).checked = false;
        await saveSettings({ resolveShorteners: false });
        setShortenerStatus(
          "Looking up shortened links needs permission to reach the shortening " +
            "services themselves. Without it nothing can be sent, so the feature stays off.",
          "err"
        );
        return;
      }
      setShortenerStatus("", "");
    }

    if (id === "checkUrlhaus" && $(id).checked) {
      if (!(await requestPermission(URLHAUS_ORIGINS))) {
        $(id).checked = false;
        await saveSettings({ checkUrlhaus: false });
        setUrlhausKeyStatus(
          "Checking links against URLhaus needs permission to reach urlhaus.abuse.ch. " +
            "Without it nothing can be downloaded, so the feature stays off.",
          "err"
        );
        return;
      }
      await refreshUrlhausNow();
      chrome.alarms.create(URLHAUS_ALARM, { periodInMinutes: URLHAUS_REFRESH_MINUTES });
    }

    await saveSettings({ [id]: $(id).checked });

    // Switching a feature off gives the access back. The setting alone would
    // be enough to stop the requests, but a permission the extension no
    // longer needs is one a reader has to take on trust.
    if (id === "cloudTier" && !$(id).checked) {
      await chrome.permissions.remove({ origins: ANTHROPIC_ORIGINS }).catch(() => {});
      setKeyStatus("Second opinion off. Network access to api.anthropic.com revoked.", "");
    }
    if (id === "resolveShorteners" && !$(id).checked) {
      await chrome.permissions.remove({ origins: SHORTENER_ORIGINS }).catch(() => {});
      setShortenerStatus("Shortened-link lookup off. Network access to shortening services revoked.", "");
    }
    if (id === "checkUrlhaus" && !$(id).checked) {
      await chrome.permissions.remove({ origins: URLHAUS_ORIGINS }).catch(() => {});
      await chrome.alarms.clear(URLHAUS_ALARM);
      await clearUrlhausFeed();
      setUrlhausKeyStatus("URLhaus check off. Network access to urlhaus.abuse.ch revoked, and the downloaded list has been deleted.", "");
      await renderUrlhausSyncStatus();
    }

    syncDependentState();
    flashSaved();
  })
);

$("minSeverityToWarn").addEventListener("change", async () => {
  await saveSettings({ minSeverityToWarn: $("minSeverityToWarn").value });
  flashSaved();
});

$("apiKey").addEventListener("change", async () => {
  const key = $("apiKey").value.trim();
  if (key && !looksLikeApiKey(key)) {
    setKeyStatus("That doesn't look like an Anthropic key — they start with sk-ant-.", "err");
    return;
  }
  await saveSettings({ apiKey: key });
  setKeyStatus(key ? "Key saved. Use Test to confirm it works." : "Key removed.", key ? "ok" : "");
  flashSaved();
});

$("toggleKey").addEventListener("click", () => {
  const input = $("apiKey");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  $("toggleKey").textContent = showing ? "Show" : "Hide";
});

$("testKey").addEventListener("click", async () => {
  const key = $("apiKey").value.trim();
  if (!key) {
    setKeyStatus("Enter a key first.", "err");
    return;
  }
  // Testing a key is itself a request to Anthropic, so it needs the same
  // permission the feature does — and this click is a user gesture, so it is
  // a legitimate place to ask.
  if (!(await requestPermission(ANTHROPIC_ORIGINS))) {
    setKeyStatus(
      "Testing the key means contacting api.anthropic.com, which needs your permission.",
      "err"
    );
    return;
  }

  const btn = $("testKey");
  btn.disabled = true;
  btn.textContent = "Testing…";
  setKeyStatus("Contacting the Claude API…", "");
  try {
    await verifyApiKey(key);
    await saveSettings({ apiKey: key });
    setKeyStatus("Key works. The second opinion is ready to use.", "ok");
  } catch (err) {
    setKeyStatus(err.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = "Test";
  }
});

/* ------------------------------- urlhaus key ------------------------------- */

// abuse.ch's feed download doesn't require an Auth-Key today (verified
// 2026-08-16 against the live endpoint) — the field below is accepted and
// sent when filled in, for the day that changes, but is never a precondition
// for turning the feature on.
async function refreshUrlhausNow() {
  setUrlhausKeyStatus("Contacting abuse.ch…", "");
  const result = await chrome.runtime.sendMessage({ type: "REFRESH_URLHAUS" });
  if (result?.ok) {
    setUrlhausKeyStatus("The URLhaus list is downloading and will refresh on its own from here.", "ok");
  } else if (result?.authError) {
    setUrlhausKeyStatus(result.reason, "err");
  } else {
    setUrlhausKeyStatus(result?.reason || "Couldn't reach abuse.ch.", "err");
  }
  await renderUrlhausSyncStatus();
}

$("urlhausAuthKey").addEventListener("change", async () => {
  const key = $("urlhausAuthKey").value.trim();
  await saveSettings({ urlhausAuthKey: key });
  setUrlhausKeyStatus(key ? "Key saved." : "Auth-Key removed.", "");
  // Reads the checkbox's live state, not the `settings` snapshot captured at
  // page load — checkUrlhaus may have been switched on earlier in this same
  // session, after that snapshot was taken.
  if (key && $("checkUrlhaus").checked) await refreshUrlhausNow();
  flashSaved();
});

$("toggleUrlhausKey").addEventListener("click", () => {
  const input = $("urlhausAuthKey");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  $("toggleUrlhausKey").textContent = showing ? "Show" : "Hide";
});

$("testUrlhausKey").addEventListener("click", async () => {
  if (!(await requestPermission(URLHAUS_ORIGINS))) {
    setUrlhausKeyStatus(
      "Testing this means contacting urlhaus.abuse.ch, which needs your permission.",
      "err"
    );
    return;
  }

  const btn = $("testUrlhausKey");
  btn.disabled = true;
  btn.textContent = "Testing…";
  await saveSettings({ urlhausAuthKey: $("urlhausAuthKey").value.trim() });
  await refreshUrlhausNow();
  btn.disabled = false;
  btn.textContent = "Test";
});

/* -------------------------------- model info ------------------------------ */

try {
  const info = await modelInfo();
  const dl = $("modelInfo");
  dl.textContent = "";
  const rows = [
    ["Status", "Loaded and running on this device"],
    ["Vocabulary", `${info.vocabSize.toLocaleString()} terms`],
    ["Validation accuracy", info.validationAccuracy ? `${(info.validationAccuracy * 100).toFixed(1)}%` : "—"],
    ["Built", info.trainedAt ? new Date(info.trainedAt).toLocaleDateString() : "—"],
  ];
  rows.forEach(([label, value]) => {
    dl.append(
      Object.assign(document.createElement("dt"), { textContent: label }),
      Object.assign(document.createElement("dd"), { textContent: value })
    );
  });
} catch {
  $("modelStatus").textContent = "Failed to load — rule-based checks still work.";
}

/* ---------------------------------- wipe ---------------------------------- */

$("wipe").addEventListener("click", async () => {
  if (!confirm("Delete all history, blocked senders, saved settings, and your API key?")) return;
  await chrome.storage.local.clear();
  location.reload();
});
