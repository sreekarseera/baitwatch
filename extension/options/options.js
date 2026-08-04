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

/* ---------------------------------- load ---------------------------------- */

const settings = await getSettings();

TOGGLES.forEach((id) => ($(id).checked = Boolean(settings[id])));
$("minSeverityToWarn").value = settings.minSeverityToWarn;
$("apiKey").value = settings.apiKey || "";
syncDependentState();

if (settings.cloudTier && !settings.apiKey) {
  setKeyStatus("The second opinion is on but no API key is saved, so it can't run.", "err");
}

/* --------------------------------- persist -------------------------------- */

TOGGLES.forEach((id) =>
  $(id).addEventListener("change", async () => {
    // Turning on the cloud tier without a key would silently do nothing;
    // say so rather than letting the user think it's working.
    if (id === "cloudTier" && $(id).checked && !$("apiKey").value.trim()) {
      setKeyStatus("Add your Anthropic API key below to enable this.", "err");
    }
    await saveSettings({ [id]: $(id).checked });
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
