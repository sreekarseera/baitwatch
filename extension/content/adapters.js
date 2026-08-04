// Site adapters — how to find "a message" on a given page.
//
// Content scripts are classic scripts in Manifest V3 (no ES modules), so the
// three content files share one scope via this namespace object.
//
// Every adapter returns a list of {id, element, text, sender}. `id` must be
// stable across re-scans of the same message or the scanner will re-analyze
// the same email every time the page mutates — which on Gmail is constantly.

var BaitWatch = window.BaitWatch || {};

(function () {
  "use strict";

  // Text long enough to be a message but short enough to be one message.
  const MIN_CHARS = 25;
  const MAX_CHARS = 20000;

  function cleanText(node) {
    if (!node) return "";
    return (node.innerText || node.textContent || "").replace(/\s+\n/g, "\n").trim();
  }

  // Stable-ish hash so the same message keeps the same id across re-scans.
  function hashId(prefix, text, sender) {
    const input = `${sender}|${text.slice(0, 400)}`;
    let hash = 5381;
    for (let i = 0; i < input.length; i++) hash = ((hash << 5) + hash + input.charCodeAt(i)) | 0;
    return `${prefix}-${(hash >>> 0).toString(36)}`;
  }

  function usable(text) {
    return text.length >= MIN_CHARS && text.length <= MAX_CHARS;
  }

  /* ---------------------------------- Gmail --------------------------------- */

  const gmail = {
    name: "gmail",
    matches: () => /(^|\.)mail\.google\.com$/.test(location.hostname),
    collect() {
      const found = [];
      // Gmail marks each expanded message body with role="listitem"; the body
      // itself is .a3s. Collapsed messages have no body rendered, so they are
      // skipped automatically rather than needing a filter.
      document.querySelectorAll("div.a3s").forEach((body) => {
        const text = cleanText(body);
        if (!usable(text)) return;

        const container = body.closest("[role='listitem']") || body.parentElement;
        const senderEl = container ? container.querySelector("span[email]") : null;
        const sender = senderEl ? (senderEl.getAttribute("email") || "").toLowerCase() : "";

        found.push({ id: hashId("gm", text, sender), element: body, text, sender });
      });
      return found;
    },
  };

  /* ------------------------------ WhatsApp Web ------------------------------ */

  const whatsapp = {
    name: "whatsapp",
    matches: () => /(^|\.)web\.whatsapp\.com$/.test(location.hostname),
    collect() {
      const found = [];
      // Only incoming messages ("message-in"); the user's own outgoing text is
      // not a threat to them and scanning it would be noise.
      document.querySelectorAll("div.message-in span.selectable-text").forEach((node) => {
        const text = cleanText(node);
        if (!usable(text)) return;
        const bubble = node.closest("div.message-in") || node;
        found.push({ id: hashId("wa", text, ""), element: bubble, text, sender: "" });
      });
      return found;
    },
  };

  /* ------------------------------ Telegram Web ------------------------------ */

  const telegram = {
    name: "telegram",
    matches: () => /(^|\.)web\.telegram\.org$/.test(location.hostname),
    collect() {
      const found = [];
      document.querySelectorAll(".message:not(.is-out) .text-content, .Message:not(.own) .text-content").forEach(
        (node) => {
          const text = cleanText(node);
          if (!usable(text)) return;
          found.push({ id: hashId("tg", text, ""), element: node, text, sender: "" });
        }
      );
      return found;
    },
  };

  /* --------------------------------- Generic -------------------------------- */
  // Fallback for every other site. Deliberately conservative: it only looks at
  // blocks that read like a message, because scanning whole pages produces
  // constant false positives on news articles and documentation about scams.

  const generic = {
    name: "generic",
    matches: () => true,
    collect() {
      const found = [];
      const candidates = document.querySelectorAll(
        "article, [role='article'], [role='listitem'], .message, .email-body, .msg-body, blockquote"
      );

      candidates.forEach((node) => {
        // Skip containers that merely wrap other candidates — otherwise a
        // thread and each of its messages both get scanned.
        if (node.querySelector("article, [role='article'], [role='listitem'], .message")) return;
        const text = cleanText(node);
        if (!usable(text)) return;
        found.push({ id: hashId("gen", text, ""), element: node, text, sender: "" });
      });

      return found.slice(0, 30); // hard cap so a pathological page can't hang the tab
    },
  };

  const ADAPTERS = [gmail, whatsapp, telegram, generic];

  BaitWatch.pickAdapter = function pickAdapter() {
    return ADAPTERS.find((a) => a.matches());
  };

  BaitWatch.adapterName = function adapterName() {
    const adapter = BaitWatch.pickAdapter();
    return adapter ? adapter.name : "none";
  };

  window.BaitWatch = BaitWatch;
})();
