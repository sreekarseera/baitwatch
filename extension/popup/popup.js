import {
  getHistory,
  clearHistory,
  getBlocklist,
  removeBlocked,
  getAllowlist,
  removeAllowed,
  addBlocked,
  addAllowed,
  getStats,
  getSettings,
} from "../lib/storage.js";
import { toCsv, downloadCsv } from "../lib/csv.js";
import { truncate } from "../lib/text.js";

const $ = (id) => document.getElementById(id);

const LABELS = {
  dangerous: { icon: "⛔", title: "Almost certainly a scam" },
  suspicious: { icon: "⚠️", title: "Treat this with caution" },
  safe: { icon: "✅", title: "Nothing suspicious found" },
};

/* ---------------------------------- tabs ---------------------------------- */

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((t) => {
      t.classList.toggle("active", t === tab);
      t.setAttribute("aria-selected", String(t === tab));
    });
    document.querySelectorAll(".panel").forEach((p) => {
      p.classList.toggle("active", p.id === `panel-${tab.dataset.panel}`);
    });
  });
});

$("openSettings").addEventListener("click", () => chrome.runtime.openOptionsPage());

/* -------------------------------- analysis -------------------------------- */

function renderResult(result) {
  const el = $("result");
  el.hidden = false;
  el.className = `result ${result.verdict}`;
  el.textContent = "";

  const label = LABELS[result.verdict] || LABELS.suspicious;

  const head = document.createElement("div");
  head.className = "head";
  head.append(
    Object.assign(document.createElement("span"), { textContent: label.icon }),
    Object.assign(document.createElement("span"), { textContent: label.title }),
    Object.assign(document.createElement("span"), {
      className: "score",
      textContent: `risk ${result.score}/100`,
    })
  );

  const body = document.createElement("div");
  body.className = "body";

  if (result.pageContext) {
    let host = result.pageContext.url || "";
    try {
      host = new URL(result.pageContext.url).hostname;
    } catch {
      /* keep the raw string if it isn't a parseable URL */
    }
    const scanned = document.createElement("p");
    scanned.className = "scanned";
    scanned.textContent =
      `Checked this whole page (${host}) — its text, ` +
      `${result.urls?.length || 0} link${result.urls?.length === 1 ? "" : "s"} on it, ` +
      `and the site's own address.`;
    body.append(scanned);
  }

  if (result.explanation) {
    body.append(
      Object.assign(document.createElement("p"), { className: "lede", textContent: result.explanation })
    );
  }

  if (result.reasons?.length) {
    const ul = document.createElement("ul");
    result.reasons.slice(0, 5).forEach((r) => {
      ul.append(Object.assign(document.createElement("li"), { textContent: r.detail }));
    });
    body.append(ul);
  } else if (result.verdict === "safe") {
    body.append(
      Object.assign(document.createElement("p"), {
        className: "lede",
        textContent:
          "No scam tactics found — no credential requests, payment pressure, or suspicious links.",
      })
    );
  }

  if (result.advice) {
    body.append(
      Object.assign(document.createElement("p"), { className: "advice", textContent: result.advice })
    );
  }

  const sender = $("sender").value.trim().toLowerCase();
  if (sender) {
    const actions = document.createElement("div");
    actions.className = "actions";

    if (result.verdict !== "safe") {
      const block = Object.assign(document.createElement("button"), {
        className: "primary small",
        textContent: `Block ${sender}`,
      });
      block.addEventListener("click", async () => {
        await addBlocked(sender);
        block.textContent = "Blocked";
        block.disabled = true;
        renderSenders();
      });
      actions.append(block);
    }

    const allow = Object.assign(document.createElement("button"), {
      className: "ghost small",
      textContent: "Mark sender safe",
    });
    allow.addEventListener("click", async () => {
      await addAllowed(sender);
      allow.textContent = "Marked safe";
      allow.disabled = true;
      renderSenders();
    });
    actions.append(allow);
    body.append(actions);
  }

  // Every address the page mentions, each one blockable in a click. On a
  // webmail page the sender is in here; on a scam page so is the "support"
  // address they want you to write to.
  const pageEmails = (result.pageContext?.emails || []).filter((e) => e !== sender);
  if (pageEmails.length) {
    body.append(
      Object.assign(document.createElement("p"), {
        className: "scanned",
        textContent: `Other addresses on this page — tap one to block it:`,
      })
    );
    const chips = document.createElement("div");
    chips.className = "chips";
    pageEmails.slice(0, 6).forEach((email) => {
      const chip = Object.assign(document.createElement("button"), {
        className: "chip",
        textContent: email,
        title: `Block ${email}`,
      });
      chip.addEventListener("click", async () => {
        await addBlocked(email);
        chip.textContent = `${email} — blocked`;
        chip.disabled = true;
        renderSenders();
      });
      chips.append(chip);
    });
    body.append(chips);
  }

  const tier = Object.assign(document.createElement("p"), {
    className: "tier",
    textContent:
      result.tier === "claude"
        ? "Checked on your device, then confirmed with Claude."
        : "Checked entirely on your device — nothing left your computer.",
  });
  body.append(tier);

  if (result.cloudError) {
    body.append(
      Object.assign(document.createElement("p"), {
        className: "tier",
        textContent: `Second opinion unavailable: ${result.cloudError}`,
      })
    );
  }

  el.append(head, body);
}

function renderError(message) {
  const el = $("result");
  el.hidden = false;
  el.className = "result suspicious";
  el.textContent = "";
  const body = document.createElement("div");
  body.className = "body";
  body.append(Object.assign(document.createElement("p"), { textContent: message }));
  el.append(body);
}

$("analyze").addEventListener("click", async () => {
  const text = $("input").value.trim();
  if (!text) {
    renderError("Paste a message first.");
    return;
  }

  const btn = $("analyze");
  btn.disabled = true;
  btn.textContent = "Checking…";

  try {
    const result = await chrome.runtime.sendMessage({
      type: "ANALYZE",
      text,
      sender: $("sender").value.trim(),
      source: "manual",
    });
    if (!result || result.error) throw new Error(result?.error || "Analysis failed.");
    if (result.skipped) {
      renderError(`${result.sender} is on your safe-sender list, so it wasn't checked.`);
    } else {
      renderResult(result);
    }
    renderHistory();
  } catch (err) {
    renderError(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "Check message";
  }
});

/* --------------------------- talking to the page -------------------------- */

const CONTENT_SCRIPTS = ["content/adapters.js", "content/overlay.js", "content/scanner.js"];

class PageUnreachableError extends Error {}

/**
 * Send a message to the active tab's content script, injecting it first if
 * it isn't there.
 *
 * Content scripts are only injected when a page *loads*. Every tab that was
 * already open when the extension was installed or reloaded therefore has no
 * content script in it, and a plain sendMessage fails — which is by far the
 * most common cause of "can't read this page", not a restricted URL. The
 * `activeTab` permission lets us inject on demand after the user's click, so
 * this recovers silently instead of asking them to reload.
 */
async function messageActiveTab(message) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new PageUnreachableError("No active tab.");

  try {
    return await chrome.tabs.sendMessage(tab.id, message);
  } catch {
    // Not loaded yet — inject and retry once.
  }

  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: CONTENT_SCRIPTS });
  } catch {
    // Injection refused: a genuinely restricted page.
    throw new PageUnreachableError(
      "Chrome doesn't allow extensions to read this page. Browser settings pages, " +
        "the Chrome Web Store, PDF files, and the new-tab page are all off limits. " +
        "Open the message on a normal website and try again."
    );
  }

  try {
    return await chrome.tabs.sendMessage(tab.id, message);
  } catch {
    throw new PageUnreachableError(
      "Couldn't read this page. Try reloading it, then check again."
    );
  }
}

$("scanPage").addEventListener("click", async () => {
  const btn = $("scanPage");
  btn.disabled = true;
  btn.textContent = "Reading the page…";

  try {
    const page = await messageActiveTab({ type: "COLLECT_PAGE" });

    if (!page || (!page.text && !page.extraUrls?.length)) {
      renderError("There's nothing readable on this page to check.");
      return;
    }

    btn.textContent = "Checking…";

    // If the user didn't type a sender, adopt the first address found on the
    // page. Without this the verdict has nothing to attach Block/Mark-safe to,
    // and the address never reaches history.
    const typedSender = $("sender").value.trim();
    const sender = typedSender || page.emails?.[0] || "";
    if (!typedSender && sender) $("sender").value = sender;

    const result = await chrome.runtime.sendMessage({
      type: "ANALYZE",
      text: page.text,
      sender,
      // Link targets and the page's own address. On a fake sign-in page these
      // are where the danger is — the visible text is designed to look normal.
      extraUrls: page.extraUrls,
      source: "page",
      // What the page claims to be, where it's served from, and what it's
      // asking for — the inputs to the impersonation check.
      page: {
        url: page.url,
        title: page.title,
        credentialFields: page.credentialFields || [],
        formTargets: page.formTargets || [],
      },
    });

    if (!result || result.error) throw new Error(result?.error || "Analysis failed.");
    if (result.skipped) {
      renderError(`${result.sender} is on your safe-sender list, so this page wasn't checked.`);
      return;
    }
    renderResult({
      ...result,
      pageContext: {
        url: page.url,
        title: page.title,
        truncated: page.truncated,
        emails: page.emails || [],
      },
    });
    renderHistory();
  } catch (err) {
    renderError(err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = "🔎 Scan this entire page";
  }
});

$("useSelection").addEventListener("click", async () => {
  try {
    const response = await messageActiveTab({ type: "GET_SELECTION" });
    if (response?.text) {
      $("input").value = response.text;
      $("result").hidden = true;
    } else {
      renderError("Nothing is selected on the page. Highlight some text first, then try again.");
    }
  } catch (err) {
    renderError(err.message);
  }
});

/* --------------------------------- history -------------------------------- */

async function renderHistory() {
  const [history, stats] = await Promise.all([getHistory(), getStats()]);
  const list = $("history");
  list.textContent = "";

  $("statLine").textContent = `${stats.scanned} checked · ${stats.flagged} flagged`;
  $("historyEmpty").hidden = history.length > 0;

  history
    .slice()
    .reverse()
    .slice(0, 100)
    .forEach((entry) => {
      const li = document.createElement("li");
      li.append(
        Object.assign(document.createElement("span"), { className: `dot ${entry.verdict}` })
      );

      const wrap = document.createElement("div");
      wrap.className = "entry";
      wrap.append(
        Object.assign(document.createElement("div"), {
          className: "text",
          textContent: truncate(entry.text, 52),
        }),
        Object.assign(document.createElement("div"), {
          className: "meta",
          textContent: [
            `${entry.score}/100`,
            entry.sender || null,
            entry.source,
            new Date(entry.timestamp).toLocaleDateString(),
          ]
            .filter(Boolean)
            .join(" · "),
        })
      );
      li.title = entry.explanation || "";
      li.append(wrap);
      list.append(li);
    });
}

$("exportHistory").addEventListener("click", async () => {
  const history = await getHistory();
  if (!history.length) return;
  downloadCsv(
    toCsv(history, ["timestamp", "verdict", "score", "sender", "source", "tier", "text", "explanation"]),
    "baitwatch-history.csv"
  );
});

$("clearHistory").addEventListener("click", async () => {
  await clearHistory();
  renderHistory();
});

/* --------------------------------- senders -------------------------------- */

function renderSenderList(listEl, emptyEl, emails, onRemove) {
  listEl.textContent = "";
  emptyEl.hidden = emails.length > 0;
  emails.forEach((email) => {
    const li = document.createElement("li");
    li.append(Object.assign(document.createElement("span"), { className: "mono", textContent: email }));
    const btn = Object.assign(document.createElement("button"), {
      className: "remove",
      textContent: "✕",
      title: `Remove ${email}`,
    });
    btn.addEventListener("click", async () => {
      await onRemove(email);
      renderSenders();
    });
    li.append(btn);
    listEl.append(li);
  });
}

async function renderSenders() {
  const [blocklist, allowlist] = await Promise.all([getBlocklist(), getAllowlist()]);
  renderSenderList($("blocklist"), $("blocklistEmpty"), blocklist, removeBlocked);
  renderSenderList($("allowlist"), $("allowlistEmpty"), allowlist, removeAllowed);
}

$("exportBlocklist").addEventListener("click", async () => {
  const blocklist = await getBlocklist();
  if (!blocklist.length) return;
  downloadCsv(toCsv(blocklist.map((email) => ({ email })), ["email"]), "baitwatch-blocklist.csv");
});

/* ---------------------------------- footer -------------------------------- */

async function renderFooter() {
  const settings = await getSettings();
  const parts = [settings.autoScan ? "Auto-scan on" : "Auto-scan off"];
  parts.push(settings.cloudTier && settings.apiKey ? "Claude second opinion on" : "On-device only");
  $("footer").textContent = parts.join(" · ");
}

/* ----------------------------- adapter health ----------------------------- */

/**
 * Ask the current tab whether auto-scan is still finding anything.
 *
 * Deliberately quiet: a plain sendMessage with no injection fallback, because
 * this runs on every popup open and having no content script is the ordinary
 * case (a restricted page, a tab older than the extension). Only a confirmed
 * breakage is worth a word to the user; everything else stays silent.
 */
async function renderAdapterHealth() {
  let health;
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    health = await chrome.tabs.sendMessage(tab.id, { type: "GET_HEALTH" });
  } catch {
    return; // no content script in this tab
  }

  if (!health || health.status !== "broken" || !health.autoScan) return;

  const alert = $("adapterAlert");
  alert.textContent =
    `Auto-scan isn't finding messages on ${health.label || "this page"} any more — ` +
    `the site has probably changed its layout. Checking by hand still works: ` +
    `select the text and use “Use selection”, or scan the whole page.`;
  alert.hidden = false;
}

renderHistory();
renderSenders();
renderFooter();
renderAdapterHealth();
