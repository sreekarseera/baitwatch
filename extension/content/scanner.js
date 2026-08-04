// Content script entry point.
//
// This file does DOM work only. All analysis happens in the service worker,
// so the model is parsed once per browser session instead of once per tab, and
// no detection logic runs inside a page's origin.

(function () {
  "use strict";

  // The popup injects these scripts on demand when a tab predates the
  // extension being installed or reloaded. That can land on top of an
  // already-running copy, so bail out rather than registering a second set of
  // message listeners and a second MutationObserver.
  if (window.__baitwatchScannerLoaded) return;
  window.__baitwatchScannerLoaded = true;

  const PD = window.BaitWatch;
  if (!PD || !PD.pickAdapter) return;

  const adapter = PD.pickAdapter();
  if (!adapter) return;

  // Messages already handled this page-load. Auto-scanning means the same
  // Gmail thread is re-collected on every DOM mutation; without this the
  // extension would re-analyze (and re-render) constantly.
  const handled = new Map(); // id -> "pending" | "done" | "dismissed"

  let settings = null;
  let enabled = true;

  const SEVERITY_RANK = { safe: 0, suspicious: 1, dangerous: 2 };

  async function loadSettings() {
    settings = await chrome.runtime.sendMessage({ type: "GET_SETTINGS" }).catch(() => null);
    if (!settings) return false;

    enabled =
      settings.autoScan &&
      ((adapter.name === "gmail" && settings.scanGmail) ||
        ((adapter.name === "whatsapp" || adapter.name === "telegram") && settings.scanChat) ||
        (adapter.name === "generic" && settings.scanGeneric));
    return enabled;
  }

  function shouldWarn(result) {
    const min = SEVERITY_RANK[settings?.minSeverityToWarn || "suspicious"] ?? 1;
    return SEVERITY_RANK[result.verdict] >= min;
  }

  function render(message, result) {
    // Don't stack duplicates if a re-scan races the first render.
    const existing = document.querySelector(`[data-baitwatch-id="${CSS.escape(result.id)}"]`);
    if (existing) existing.remove();

    const warning = PD.buildWarning(result, {
      onBlock: (email) => chrome.runtime.sendMessage({ type: "BLOCK_SENDER", email }),
      onAllow: (email) => chrome.runtime.sendMessage({ type: "ALLOW_SENDER", email }),
      onDismiss: () => handled.set(result.id, "dismissed"),
    });

    const target = message.element;
    if (target && target.parentNode) {
      target.parentNode.insertBefore(warning, target);
    }
  }

  async function scan() {
    if (!enabled) return;

    let messages;
    try {
      messages = adapter.collect();
    } catch (err) {
      console.warn("[BaitWatch] adapter failed:", err);
      return;
    }

    for (const message of messages) {
      if (handled.has(message.id)) continue;
      handled.set(message.id, "pending");

      try {
        const result = await chrome.runtime.sendMessage({
          type: "ANALYZE",
          text: message.text,
          sender: message.sender,
          source: adapter.name,
          id: message.id,
        });

        if (handled.get(message.id) === "dismissed") continue;
        handled.set(message.id, "done");

        if (result && !result.skipped && shouldWarn(result)) {
          render(message, { ...result, id: message.id });
        }
      } catch {
        // Service worker asleep or extension reloading — retry on next pass.
        handled.delete(message.id);
      }
    }
  }

  /* ------------------------------ scheduling ------------------------------- */
  // Gmail and chat apps mutate the DOM continuously (typing indicators, read
  // receipts, virtual scrolling). A naive MutationObserver callback would fire
  // hundreds of times a second, so scans are debounced and rate-limited.

  let debounceTimer = null;
  let lastScan = 0;
  const MIN_INTERVAL_MS = 1200;

  function scheduleScan() {
    clearTimeout(debounceTimer);
    const sinceLast = Date.now() - lastScan;
    const delay = Math.max(600, MIN_INTERVAL_MS - sinceLast);
    debounceTimer = setTimeout(() => {
      lastScan = Date.now();
      scan();
    }, delay);
  }

  async function init() {
    if (!(await loadSettings())) return;
    scan();

    const observer = new MutationObserver((mutations) => {
      // Ignore mutations we caused ourselves, or the observer re-triggers on
      // every warning it inserts.
      const relevant = mutations.some((m) => {
        const nodes = [...m.addedNodes, ...m.removedNodes];
        return !nodes.some((n) => n.nodeType === 1 && n.classList?.contains("baitwatch-warning"));
      });
      if (relevant) scheduleScan();
    });

    observer.observe(document.body, { childList: true, subtree: true });

    // Single-page apps swap the whole view without a navigation event; Gmail
    // does this on every thread you open.
    let lastUrl = location.href;
    setInterval(() => {
      if (location.href !== lastUrl) {
        lastUrl = location.href;
        handled.clear();
        scheduleScan();
      }
    }, 1000);

    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== "local") return;
      if (changes.settings) loadSettings().then(() => scheduleScan());
      if (changes.blocklist || changes.allowlist) {
        handled.clear();
        scheduleScan();
      }
    });
  }

  /* ---------------------------- whole-page scan ---------------------------- */

  const PAGE_TEXT_LIMIT = 20000;
  const PAGE_LINK_LIMIT = 200;

  /**
   * Collect everything on the page worth judging.
   *
   * Visible text alone is not enough. A credential-harvest page reads
   * "Sign in to continue" and hides the hostile domain in an href, so the
   * link targets — and the page's own address — carry more signal than
   * anything the user can see. All three go to the engine.
   */
  // Duplicated from lib/text.js rather than imported: content scripts are
  // classic scripts under Manifest V3 and cannot use ES modules.
  const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

  function collectPage() {
    const text = (document.body?.innerText || "").replace(/\n{3,}/g, "\n\n").trim();

    // Addresses visible on the page. On a webmail page this is how the popup
    // learns who actually sent the thing, so Block/Mark-safe have something
    // to act on without the user retyping it.
    const emails = [...new Set((text.match(EMAIL_RE) || []).map((e) => e.toLowerCase()))].slice(0, 20);

    // mailto: links carry the sender even when the address isn't rendered.
    for (const link of document.querySelectorAll('a[href^="mailto:"]')) {
      const address = link.getAttribute("href").slice(7).split("?")[0].toLowerCase();
      if (address && EMAIL_RE.test(address) && !emails.includes(address)) emails.push(address);
      EMAIL_RE.lastIndex = 0; // the regex is /g; test() would otherwise skip ahead
    }

    const links = [];
    for (const anchor of document.querySelectorAll("a[href], area[href]")) {
      const href = anchor.href; // resolved absolute URL, not the raw attribute
      if (!href || !/^https?:/i.test(href)) continue;
      links.push(href);
      if (links.length >= PAGE_LINK_LIMIT) break;
    }

    // Forms that post credentials off-site are worth surfacing even when the
    // page itself looks ordinary.
    const formTargets = [...document.querySelectorAll("form[action]")]
      .map((form) => form.action)
      .filter((action) => /^https?:/i.test(action));

    return {
      text: text.slice(0, PAGE_TEXT_LIMIT),
      truncated: text.length > PAGE_TEXT_LIMIT,
      extraUrls: [...new Set([location.href, ...links, ...formTargets])],
      title: document.title || "",
      emails,
      // Reported from here rather than read off the tab: `tab.url` requires
      // the "tabs" permission or a matching host permission, and this
      // extension deliberately requests neither.
      url: location.href,
    };
  }

  // Popup asks the active tab to scan the selection, re-scan messages, or
  // judge the whole page.
  chrome.runtime.onMessage.addListener((msg, _sender, respond) => {
    if (msg.type === "RESCAN") {
      handled.clear();
      scan().then(() => respond({ ok: true, adapter: adapter.name }));
      return true;
    }
    if (msg.type === "GET_SELECTION") {
      respond({ text: (window.getSelection()?.toString() || "").trim() });
      return false;
    }
    if (msg.type === "COLLECT_PAGE") {
      respond(collectPage());
      return false;
    }
    return false;
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
