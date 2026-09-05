// Tests for the site adapters and their health monitor.
//
// The thing being protected here is a silent failure. Gmail and WhatsApp
// rewrite their markup without notice; when a selector rots, collect() returns
// an empty list, which is indistinguishable from an empty inbox. Auto-scan
// goes quiet and nothing tells anyone. The health monitor is what notices, so
// it needs tests that pin down both halves of the judgement: it must fire when
// the selectors have genuinely broken, and it must stay silent on a page that
// simply has nothing to scan — a monitor that cries wolf gets ignored, which
// leaves the extension exactly as silent as it was before.
//
// content/adapters.js is a classic script under Manifest V3, not a module, so
// it is run in a `vm` context against a fake DOM rather than imported.
//
//     node tests/test_adapters.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const ext = join(here, "..", "extension");

let passed = 0;
const failures = [];

function check(name, condition, detail = "") {
  if (condition) passed++;
  else failures.push(`${name}${detail ? ` — ${detail}` : ""}`);
}

/* ------------------------------- fake DOM --------------------------------- */
// Just enough of the DOM for the adapters: a selector -> nodes map that each
// test sets up, and nodes that answer the handful of methods collect() calls.

function makeNode({ text = "", sender = "", parent = null } = {}) {
  const node = {
    innerText: text,
    textContent: text,
    closest: () => parent,
    querySelector: (sel) =>
      sel === "span[email]" && sender ? { getAttribute: () => sender } : null,
    parentElement: parent,
  };
  return node;
}

function makeDom(map = {}) {
  return {
    querySelectorAll: (sel) => map[sel] || [],
    querySelector: (sel) => (map[sel] || [])[0] || null,
  };
}

function load(hostname, dom) {
  const context = {
    window: {},
    document: dom,
    location: { hostname },
    console,
  };
  vm.createContext(context);
  vm.runInContext(readFileSync(join(ext, "content", "adapters.js"), "utf-8"), context);
  return context.window.BaitWatch;
}

/* --------------------------- selectors vs landmarks ------------------------ */
// The invariant that makes the whole check meaningful. A landmark exists to
// answer "did this page render a conversation?" independently of the selectors
// it vouches for. Reuse one of those selectors as a landmark and the monitor
// can never distinguish a rotted selector from an empty page — it would go
// idle at exactly the moment it is supposed to speak up.

const PD = load("mail.google.com", makeDom());
const sites = PD.adapters.filter((a) => a.name !== "generic");

for (const adapter of sites) {
  check(
    `${adapter.name}: declares landmarks`,
    Array.isArray(adapter.landmarks) && adapter.landmarks.length > 0
  );

  const overlap = adapter.landmarks.filter((landmark) =>
    adapter.selectors.some((sel) => landmark.includes(sel) || sel.includes(landmark))
  );
  check(
    `${adapter.name}: landmarks are independent of message selectors`,
    overlap.length === 0,
    `overlapping: ${overlap.join(", ")}`
  );
}

const generic = PD.adapters.find((a) => a.name === "generic");
check("generic adapter claims no landmarks", generic.landmarks.length === 0);

/* -------------------------------- routing --------------------------------- */

check("gmail adapter is picked on mail.google.com", PD.pickAdapter().name === "gmail");
check(
  "whatsapp adapter is picked on web.whatsapp.com",
  load("web.whatsapp.com", makeDom()).pickAdapter().name === "whatsapp"
);
check(
  "an ordinary site falls back to generic",
  load("news.ycombinator.com", makeDom()).pickAdapter().name === "generic"
);
check(
  "a lookalike hostname does not match Gmail",
  load("mail.google.com.evil.tk", makeDom()).pickAdapter().name === "generic"
);

/* ----------------------- selectors still find messages --------------------- */
// Guards the refactor that made the selectors declarative: collect() and the
// `selectors` array the health check reasons about must stay the same strings.

const BODY = "Your account will be blocked. Share the OTP to complete verification.";
const container = makeNode({ text: BODY, sender: "scammer@example.com" });
const gmailDom = makeDom({
  "div.a3s": [makeNode({ text: BODY, sender: "scammer@example.com", parent: container })],
});
const gmailPD = load("mail.google.com", gmailDom);
const collected = gmailPD.pickAdapter().collect();

check("gmail collect() finds a message body", collected.length === 1);
check("gmail collect() reads the sender", collected[0]?.sender === "scammer@example.com");
check("collected messages carry a stable id", Boolean(collected[0]?.id?.startsWith("gm-")));
check(
  "the same message keeps the same id across scans",
  gmailPD.pickAdapter().collect()[0]?.id === collected[0]?.id
);

/* ----------------------------- health monitor ------------------------------ */

const gmailAdapter = PD.adapters.find((a) => a.name === "gmail");

// `present` is injected so these cases can state what the page looks like
// without building a DOM for each one.
function monitor(present) {
  return PD.createHealthMonitor(gmailAdapter, { present: () => present });
}

check("a scan that finds messages reports ok", monitor(true).record(3) === "ok");

// An empty inbox, a collapsed thread, a chat list with nothing open. The
// landmark is absent, so there is no claim to make.
const idle = monitor(false);
let idleStatus;
for (let i = 0; i < 10; i++) idleStatus = idle.record(0, { now: i * 60000 });
check("nothing rendered stays idle however long it lasts", idleStatus === "idle");

// The case that matters: the page is plainly showing a conversation and the
// adapter keeps coming back empty.
const breaking = monitor(true);
check("first empty scan on a populated page is not yet a verdict",
  breaking.record(0, { now: 0 }) === "watching");
check("nor is the second", breaking.record(0, { now: 1000 }) === "watching");
check(
  "three misses inside the window still only watches",
  breaking.record(0, { now: 2000 }) === "watching"
);
check(
  "sustained misses on a populated page are called broken",
  breaking.record(0, { now: 11000 }) === "broken"
);

// Gmail paints its message list a beat before the bodies, so a burst of empty
// scans in the first second of a thread opening is normal and must not count.
const burst = monitor(true);
let burstStatus;
for (let i = 0; i < 8; i++) burstStatus = burst.record(0, { now: i * 200 });
check("a fast burst of empty scans is not enough on its own", burstStatus === "watching");

const recovering = monitor(true);
recovering.record(0, { now: 0 });
recovering.record(0, { now: 6000 });
recovering.record(0, { now: 12000 });
check("precondition: recovering monitor is broken", recovering.status === "broken");
check("finding a message clears the alarm", recovering.record(2, { now: 13000 }) === "ok");
check(
  "and the run starts over rather than tripping immediately",
  recovering.record(0, { now: 14000 }) === "watching"
);

// A selector that throws is broken by definition; waiting for corroboration
// would only delay the news.
check("a collect() that throws is broken at once",
  monitor(true).record(0, { threw: true }) === "broken");

// The generic adapter runs on every site on the web, where finding nothing
// message-shaped is the ordinary outcome. It must never accuse itself.
const genericMonitor = PD.createHealthMonitor(generic, { present: () => true });
let genericStatus;
for (let i = 0; i < 10; i++) genericStatus = genericMonitor.record(0, { now: i * 60000 });
check("the generic adapter never reports a breakage", genericStatus === "unknown");

// content/scanner.js builds the monitor at load time, above the point where it
// registers its message listener, so a monitor that throws on an unexpected
// adapter would take auto-scan, warning rendering and the popup's page scan
// down with it. An adapter with no `landmarks` field — an older injected copy
// of adapters.js looks exactly like this — must degrade to "unknown", not throw.
let legacy;
try {
  legacy = PD.createHealthMonitor({ name: "legacy", selectors: [] });
} catch (err) {
  legacy = err;
}
check(
  "an adapter with no landmarks field yields a monitor rather than throwing",
  Boolean(legacy) && typeof legacy.record === "function",
  String(legacy)
);
check(
  "and that monitor stays at unknown instead of accusing anyone",
  legacy?.record?.(0, { now: 99000 }) === "unknown"
);

/* --------------------- scanner.js: virtualized-feed recycling --------------- */
// content/scanner.js (2026-09-05 fix). X's timeline, and any other virtualized
// infinite-scroll feed, reuses the same <article> DOM node for a new message
// as the user scrolls. scanner.js's `handled` map is keyed by a content hash,
// not by element, so nothing previously noticed when a node's *content*
// changed out from under an already-rendered banner — the banner, inserted as
// a plain DOM sibling, just stayed there, permanently, next to whatever
// unrelated text later scrolled into that position. This regression-tests the
// fix directly against the real content scripts (adapters.js, overlay.js,
// scanner.js), not a reimplementation of their logic, using a hand-built fake
// DOM — the same approach the health-monitor tests above use, extended with
// just enough of a live parent/child tree (insertBefore, remove) and an
// attribute-selector lookup for `[data-baitwatch-id="..."]` to let render()'s
// dedup and scan()'s stale-banner cleanup actually run.
//
// This is the DOM/rendering half of the 2026-09-05 fix; the engine-side half
// (crypto_transfer requiring reader-direction) is covered by
// tests/test_engine.mjs and tests/holdout-ambient.json instead. Untested here:
// the real browser layer (a real Chrome tab, a real MutationObserver actually
// firing on real mutations) — that needs python3 tests/run_all.py with a
// working Chrome for Testing checkout, which see docs/PROGRESS.md for.

function fakeElement(tag) {
  return {
    tagName: tag,
    className: "",
    dataset: {},
    children: [],
    parentNode: null,
    innerText: "",
    textContent: "",
    disabled: false,
    attachShadow() {
      return fakeElement("#shadow-root");
    },
    appendChild(child) {
      this.children.push(child);
      child.parentNode = this;
      return child;
    },
    append(...kids) {
      kids.forEach((k) => this.appendChild(k));
    },
    insertBefore(newNode, refNode) {
      const idx = this.children.indexOf(refNode);
      this.children.splice(idx === -1 ? this.children.length : idx, 0, newNode);
      newNode.parentNode = this;
      return newNode;
    },
    removeChild(child) {
      const idx = this.children.indexOf(child);
      if (idx !== -1) this.children.splice(idx, 1);
      child.parentNode = null;
      return child;
    },
    remove() {
      if (this.parentNode) this.parentNode.removeChild(this);
    },
    setAttribute() {},
    getAttribute() {
      return null;
    },
    addEventListener() {},
    querySelector() {
      return null;
    },
    closest() {
      return null;
    },
  };
}

const GENERIC_SELECTOR =
  "article, [role='article'], [role='listitem'], .message, .email-body, .msg-body, blockquote";

// Loads the three real classic scripts into one vm context sharing `window`,
// against a feed containing a single recyclable <article>, and wires just
// enough of chrome.runtime for scanner.js's init() to run for real: settings
// load, one ANALYZE round-trip per message, and a RESCAN entry point this
// test uses to drive a second pass by hand (standing in for the
// MutationObserver callback a real scroll would trigger).
function loadScanner({ hostname, articleText, verdictFor }) {
  const feed = fakeElement("div");
  const article = fakeElement("article");
  article.innerText = articleText;
  feed.appendChild(article);

  let onMessageListener = null;

  const fakeDocument = {
    body: fakeElement("body"),
    readyState: "complete",
    createElement: (tag) => fakeElement(tag),
    querySelectorAll: (sel) => (sel === GENERIC_SELECTOR ? [article] : []),
    querySelector: (sel) => {
      const m = /^\[data-baitwatch-id="(.*)"\]$/.exec(sel);
      if (!m) return null;
      return feed.children.find((c) => c.dataset && c.dataset.baitwatchId === m[1]) || null;
    },
  };

  const context = {
    window: {},
    document: fakeDocument,
    location: { hostname, href: `https://${hostname}/home` },
    console,
    CSS: { escape: (s) => s },
    MutationObserver: class {
      observe() {}
      disconnect() {}
    },
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id),
    chrome: {
      runtime: {
        sendMessage: (msg) => {
          if (msg.type === "GET_SETTINGS") {
            return Promise.resolve({
              autoScan: true,
              scanGeneric: true,
              scanGmail: true,
              scanChat: true,
              minSeverityToWarn: "suspicious",
            });
          }
          if (msg.type === "ANALYZE") return Promise.resolve(verdictFor(msg.text));
          return Promise.resolve(null);
        },
        onMessage: {
          addListener: (fn) => {
            onMessageListener = fn;
          },
        },
      },
      storage: { onChanged: { addListener: () => {} } },
    },
  };

  vm.createContext(context);
  for (const file of ["adapters.js", "overlay.js", "scanner.js"]) {
    vm.runInContext(readFileSync(join(ext, "content", file), "utf-8"), context);
  }

  return {
    feed,
    article,
    rescan: () => new Promise((resolve) => onMessageListener({ type: "RESCAN" }, {}, resolve)),
  };
}

// Every chrome.runtime call above resolves via Promise.resolve(), so draining
// a handful of microtask turns is enough to let init()'s fire-and-forget first
// scan (loadSettings -> collect -> ANALYZE -> render) settle before asserting
// on it.
async function settle() {
  for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
}

{
  const TEXT1 = "Original tweet asking for a Bitcoin payment right now.";
  const TEXT2 = "Completely unrelated later tweet about something else entirely.";

  const scanner = loadScanner({
    hostname: "x.com",
    articleText: TEXT1,
    verdictFor: (text) =>
      text === TEXT1
        ? {
            verdict: "dangerous",
            score: 82,
            reasons: [{ id: "crypto_transfer", detail: "It asks you to send cryptocurrency." }],
            skipped: false,
          }
        : { verdict: "safe", score: 0, reasons: [], skipped: false },
  });
  await settle();

  const firstBanner = scanner.feed.children.find((c) => c !== scanner.article);
  check(
    "scanner: first scan renders a banner next to the article",
    Boolean(firstBanner),
    `feed has ${scanner.feed.children.length} children`
  );
  const staleId = firstBanner?.dataset?.baitwatchId;
  check(
    "scanner: the article is tagged with the banner's content hash",
    Boolean(staleId) && scanner.article.dataset.baitwatchSourceId === staleId
  );

  // Virtualization: the feed recycles this exact <article> node for a new,
  // unrelated message as the user scrolls. Nothing removed the old banner
  // before this fix — it stayed put, permanently attached to whatever content
  // later scrolled into this position. Standing in for the MutationObserver
  // callback a real scroll would fire, RESCAN is this test's hand-driven
  // second pass over the same (now recycled) node.
  scanner.article.innerText = TEXT2;
  await scanner.rescan();

  check(
    "scanner: recycling the article's content removes the stale banner",
    !scanner.feed.children.some((c) => c.dataset && c.dataset.baitwatchId === staleId)
  );
  check(
    "scanner: no banner lingers for the new content when it doesn't warrant one",
    scanner.feed.children.length === 1 && scanner.feed.children[0] === scanner.article,
    `feed has ${scanner.feed.children.length} children`
  );
}

{
  // The other half: the recycled-in content is *also* dangerous. The stale
  // banner still has to go — it was built from the old analysis, wrong
  // reasons and all — and exactly one fresh banner, tagged for the new
  // content, should take its place.
  const TEXT1 = "First message about winning a prize you must claim now.";
  const TEXT2 = "Second unrelated message asking you to send Bitcoin to this wallet.";

  const scanner = loadScanner({
    hostname: "x.com",
    articleText: TEXT1,
    verdictFor: (text) => ({
      verdict: "dangerous",
      score: 80,
      reasons: [{ id: text === TEXT1 ? "prize_or_windfall" : "crypto_transfer", detail: "..." }],
      skipped: false,
    }),
  });
  await settle();

  const firstBanner = scanner.feed.children.find((c) => c !== scanner.article);
  const firstId = firstBanner?.dataset?.baitwatchId;

  scanner.article.innerText = TEXT2;
  await scanner.rescan();

  const banners = scanner.feed.children.filter((c) => c !== scanner.article);
  check(
    "scanner: recycled content that also warrants a banner ends up with exactly one, not two",
    banners.length === 1,
    `feed has ${banners.length} banner(s)`
  );
  check(
    "scanner: the surviving banner is tagged for the new content, not the old",
    Boolean(firstId) &&
      banners[0]?.dataset?.baitwatchId !== firstId &&
      scanner.article.dataset.baitwatchSourceId === banners[0]?.dataset?.baitwatchId
  );
}

/* ---------------------------------- report --------------------------------- */

const total = passed + failures.length;
console.log(`\n${passed}/${total} checks passed`);

if (failures.length) {
  console.log("\nFailures:");
  failures.forEach((f) => console.log(`  ✗ ${f}`));
  process.exit(1);
}
console.log("All adapter checks passed.");
