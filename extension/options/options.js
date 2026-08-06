import { getSettings, saveSettings } from "../lib/storage.js";
import { looksLikeApiKey, verifyApiKey } from "../engine/claude.js";
import { modelInfo } from "../engine/model.js";

const $ = (id) => document.getElementById(id);

const TOGGLES = ["autoScan", "scanGmail", "scanChat", "scanGeneric", "cloudTier"];

let savedTimer = null;
function flashSaved() {
  const el = $("saved");
  el.hidden = false;
  clearTimeout(savedTimer);
  savedTimer = setTimeout(() => (el.hidden = true), 1400);
}

function setKeyStatus(message, kind) {
  const el = $("keyStatus");
  el.hidden = !message;
  el.textContent = message;
  el.className = `status ${kind || ""}`;
}

function syncDependentState() {
  document.querySelector(".indent").classList.toggle("disabled", !$("autoScan").checked);
}

/* --------------------------- network permission --------------------------- */
// Reaching api.anthropic.com is an optional host permission, not one granted
// at install. The extension's central claim is that nothing leaves your
// machine; a permission every user must grant on install to enable a feature
// that is off by default contradicts that at exactly the moment they are
// deciding whether to trust it. Requesting it here, when the user switches
// the second opinion on, makes the grant mean what it says — and revoking it
// when they switch back off means turning the feature off actually takes the
// ability away rather than just setting a flag.
//
// Chrome only honours permissions.request() during a user gesture, which is
// why every call below hangs off a click or a change event.

const ANTHROPIC_ORIGIN = "https://api.anthropic.com/*";

function hasNetworkPermission() {
  return chrome.permissions.contains({ origins: [ANTHROPIC_ORIGIN] });
}

async function requestNetworkPermission() {
  if (await hasNetworkPermission()) return true;
  try {
    return await chrome.permissions.request({ origins: [ANTHROPIC_ORIGIN] });
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
syncDependentState();

if (settings.cloudTier && !settings.apiKey) {
  setKeyStatus("The second opinion is on but no API key is saved, so it can't run.", "err");
} else if (settings.cloudTier && !(await hasNetworkPermission())) {
  // Chrome lets a user revoke host access from chrome://extensions without
  // telling the extension. The setting would still read "on" and every scan
  // would fail one at a time; say it once, here, instead.
  setKeyStatus(
    "Permission to reach api.anthropic.com was revoked, so the second opinion " +
      "cannot run. Switch it off and on again to restore it.",
    "err"
  );
}

/* --------------------------------- persist -------------------------------- */

TOGGLES.forEach((id) =>
  $(id).addEventListener("change", async () => {
    if (id === "cloudTier" && $(id).checked) {
      // Ask for network access at the moment the feature is switched on. A
      // refusal has to switch the toggle back: leaving it on would promise a
      // second opinion the extension has no way to fetch.
      if (!(await requestNetworkPermission())) {
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

    await saveSettings({ [id]: $(id).checked });

    // Switching it off gives the access back. The setting alone would be
    // enough to stop the requests, but a permission the extension no longer
    // needs is one a reader has to take on trust.
    if (id === "cloudTier" && !$(id).checked) {
      await chrome.permissions.remove({ origins: [ANTHROPIC_ORIGIN] }).catch(() => {});
      setKeyStatus("Second opinion off. Network access to api.anthropic.com revoked.", "");
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
  if (!(await requestNetworkPermission())) {
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
