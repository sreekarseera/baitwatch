// Site adapters — how to find "a message" on a given page.
//
// Content scripts are classic scripts in Manifest V3 (no ES modules), so the
// three content files share one scope via this namespace object.
//
// Every adapter returns a list of {id, element, text, sender}. `id` must be
// stable across re-scans of the same message or the scanner will re-analyze
// the same email every time the page mutates — which on Gmail is constantly.
//
// Each site adapter also declares `landmarks`: selectors that say the app has
// rendered a conversation at all. Gmail and WhatsApp change their markup
// without notice, and a `collect()` whose selectors have rotted returns an
// empty list — exactly what an empty inbox returns. Auto-scan then goes quiet
// and nothing anywhere notices. Landmarks are what tell the two apart, so they
// must not overlap with the selectors they vouch for: a landmark is only
// evidence that a message selector broke if it can still match when that
// selector no longer does. Prefer ARIA roles and structural ids, which survive
// the class-name churn that breaks the message selectors in the first place.
// tests/test_adapters.mjs enforces the no-overlap rule.

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
    label: "Gmail",
    matches: () => /(^|\.)mail\.google\.com$/.test(location.hostname),
    selectors: ["div.a3s"],
    // An open thread renders its messages as list items inside the main
    // region. That structure is ARIA, not styling, so it outlives `.a3s`.
    landmarks: ["[role='main'] [role='listitem']"],
    collect() {
      const found = [];
      // Gmail marks each expanded message body with role="listitem"; the body
      // itself is .a3s. Collapsed messages have no body rendered, so they are
      // skipped automatically rather than needing a filter.
      document.querySelectorAll(gmail.selectors[0]).forEach((body) => {
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
    label: "WhatsApp Web",
    matches: () => /(^|\.)web\.whatsapp\.com$/.test(location.hostname),
    selectors: ["div.message-in span.selectable-text"],
    // #main is the open conversation pane; each message is a role="row".
    landmarks: ["#main [role='row']"],
    collect() {
      const found = [];
      // Only incoming messages ("message-in"); the user's own outgoing text is
      // not a threat to them and scanning it would be noise.
      document.querySelectorAll(whatsapp.selectors[0]).forEach((node) => {
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
    label: "Telegram Web",
    matches: () => /(^|\.)web\.telegram\.org$/.test(location.hostname),
    // Telegram ships two clients on the same origin — /k/ and /a/ — with
    // different markup, so both are covered here.
    selectors: [".message:not(.is-out) .text-content", ".Message:not(.own) .text-content"],
    landmarks: [".bubbles", "#MiddleColumn"],
    collect() {
      const found = [];
      document.querySelectorAll(telegram.selectors.join(", ")).forEach(
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
    label: "this page",
    matches: () => true,
    selectors: [
      "article, [role='article'], [role='listitem'], .message, .email-body, .msg-body, blockquote",
    ],
    // No landmarks, and none are possible: on an arbitrary page, finding
    // nothing message-shaped is the ordinary outcome, not a symptom. The
    // health monitor reports "unknown" here rather than guessing.
    landmarks: [],
    collect() {
      const found = [];
      const candidates = document.querySelectorAll(generic.selectors[0]);

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

  BaitWatch.adapters = ADAPTERS; // for tests

  /* ------------------------------- health ---------------------------------- */

  // A scan that finds nothing is only suspicious if the page is plainly
  // showing a conversation, and even then only if it keeps happening: Gmail
  // renders its message list a beat before the bodies, so the first empty pass
  // on a freshly opened thread is normal. Both a count and a duration have to
  // be exceeded before the adapter is called broken.
  const MISSES_BEFORE_BROKEN = 3;
  const MISS_WINDOW_MS = 10000;

  // ok      — messages were found last scan
  // idle    — the app isn't showing a conversation; nothing to find
  // unknown — no landmarks to judge by (the generic adapter)
  // watching— empty on a page that looks populated, not yet long enough
  // broken  — the selectors have almost certainly rotted
  BaitWatch.createHealthMonitor = function createHealthMonitor(adapter, deps = {}) {
    const present =
      deps.present || (() => adapter.landmarks.some((sel) => document.querySelector(sel)));

    let misses = 0;
    let firstMissAt = 0;
    let status = adapter.landmarks.length ? "ok" : "unknown";

    return {
      get status() {
        return status;
      },

      /**
       * Fold one scan's outcome into the running state.
       *
       * @param {number} count   messages the adapter returned
       * @param {object} [opts]  `threw` if collect() raised, `now` for tests
       * @returns {string} the status after this scan
       */
      record(count, opts = {}) {
        const now = opts.now ?? Date.now();

        // An exception needs no corroboration — a selector that throws is
        // broken by definition, and waiting three scans to say so would only
        // delay the news.
        if (opts.threw) {
          misses = 0;
          firstMissAt = 0;
          status = "broken";
          return status;
        }

        if (count > 0) {
          misses = 0;
          firstMissAt = 0;
          status = "ok";
          return status;
        }

        if (!adapter.landmarks.length) {
          status = "unknown";
          return status;
        }

        if (!present()) {
          // Inbox list, empty chat, nothing open. Not evidence either way, so
          // clear the run rather than letting idle time accumulate into a
          // false accusation.
          misses = 0;
          firstMissAt = 0;
          status = "idle";
          return status;
        }

        misses += 1;
        if (misses === 1) firstMissAt = now;
        status =
          misses >= MISSES_BEFORE_BROKEN && now - firstMissAt >= MISS_WINDOW_MS
            ? "broken"
            : "watching";
        return status;
      },
    };
  };

  window.BaitWatch = BaitWatch;
})();
