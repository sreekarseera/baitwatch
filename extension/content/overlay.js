// In-page warning UI.
//
// Everything renders inside a closed shadow root with an all-properties reset.
// Without that, host-page CSS leaks in and a warning banner on a hostile page
// can be styled into invisibility — which is exactly the page that most needs
// the warning to be readable.

var BaitWatch = window.BaitWatch || {};

(function () {
  "use strict";

  const STYLE = `
    :host { all: initial; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    .wrap {
      all: initial;
      display: block;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
      font-size: 13px;
      line-height: 1.5;
      color: #1a1a1a;
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 2px 12px rgba(0,0,0,.18);
      margin: 10px 0;
    }
    .head {
      display: flex; align-items: center; gap: 8px;
      padding: 10px 12px; font-weight: 600; color: #fff;
      font-size: 13px;
    }
    .dangerous .head { background: #b3261e; }
    .suspicious .head { background: #a2660a; }
    .safe .head { background: #1b6b3a; }
    .head .score { margin-left: auto; font-weight: 500; opacity: .9; font-size: 12px; }
    .body { background: #fff; padding: 12px; }
    .lede { margin-bottom: 8px; }
    ul { list-style: none; }
    li { position: relative; padding-left: 16px; margin-bottom: 6px; color: #333; }
    li::before { content: "•"; position: absolute; left: 4px; color: #999; }
    .advice {
      margin-top: 10px; padding: 8px 10px; background: #f4f4f5;
      border-left: 3px solid #999; border-radius: 4px; color: #333;
    }
    .actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
    button {
      all: unset; cursor: pointer; padding: 6px 12px; border-radius: 6px;
      font-size: 12px; font-weight: 500; border: 1px solid #ccc; background: #fff;
      color: #1a1a1a;
    }
    button:hover { background: #f0f0f0; }
    button.primary { background: #1a1a1a; color: #fff; border-color: #1a1a1a; }
    button.primary:hover { background: #333; }
    .tier { margin-top: 10px; font-size: 11px; color: #777; }
    .close {
      all: unset; cursor: pointer; color: #fff; opacity: .8;
      font-size: 15px; line-height: 1; padding: 0 2px;
    }
    .close:hover { opacity: 1; }
  `;

  const LABELS = {
    dangerous: { icon: "⛔", title: "Almost certainly a scam" },
    suspicious: { icon: "⚠️", title: "Treat this with caution" },
    safe: { icon: "✅", title: "Nothing suspicious found" },
  };

  /**
   * @param {object} result verdict from the engine
   * @param {{onBlock, onAllow, onDismiss}} handlers
   * @returns {HTMLElement} host element to insert into the page
   */
  BaitWatch.buildWarning = function buildWarning(result, handlers = {}) {
    const host = document.createElement("div");
    host.className = "baitwatch-warning";
    host.dataset.baitwatchId = result.id || "";
    const root = host.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = STYLE;

    const wrap = document.createElement("div");
    wrap.className = `wrap ${result.verdict}`;

    const label = LABELS[result.verdict] || LABELS.suspicious;

    // Header
    const head = document.createElement("div");
    head.className = "head";
    const icon = document.createElement("span");
    icon.textContent = label.icon;
    const title = document.createElement("span");
    title.textContent = label.title;
    const score = document.createElement("span");
    score.className = "score";
    score.textContent = `risk ${result.score}/100`;
    const close = document.createElement("button");
    close.className = "close";
    close.textContent = "✕";
    close.setAttribute("aria-label", "Dismiss warning");
    close.addEventListener("click", () => {
      host.remove();
      handlers.onDismiss?.();
    });
    head.append(icon, title, score, close);

    // Body
    const body = document.createElement("div");
    body.className = "body";

    if (result.explanation) {
      const lede = document.createElement("p");
      lede.className = "lede";
      lede.textContent = result.explanation;
      body.appendChild(lede);
    }

    if (result.reasons?.length) {
      const list = document.createElement("ul");
      result.reasons.slice(0, 4).forEach((reason) => {
        const li = document.createElement("li");
        li.textContent = reason.detail;
        list.appendChild(li);
      });
      body.appendChild(list);
    }

    if (result.advice) {
      const advice = document.createElement("p");
      advice.className = "advice";
      advice.textContent = result.advice;
      body.appendChild(advice);
    }

    // Actions
    const actions = document.createElement("div");
    actions.className = "actions";

    if (result.sender && result.verdict !== "safe") {
      const block = document.createElement("button");
      block.className = "primary";
      block.textContent = `Block ${result.sender}`;
      block.addEventListener("click", () => {
        handlers.onBlock?.(result.sender);
        block.textContent = "Blocked";
        block.disabled = true;
      });
      actions.appendChild(block);
    }

    if (result.sender) {
      const allow = document.createElement("button");
      allow.textContent = "This sender is fine";
      allow.addEventListener("click", () => {
        handlers.onAllow?.(result.sender);
        host.remove();
      });
      actions.appendChild(allow);
    }

    if (actions.children.length) body.appendChild(actions);

    const tier = document.createElement("p");
    tier.className = "tier";
    tier.textContent =
      result.tier === "claude"
        ? "Checked on your device, then confirmed with Claude."
        : "Checked entirely on your device — nothing was sent anywhere.";
    body.appendChild(tier);

    if (result.cloudError) {
      const err = document.createElement("p");
      err.className = "tier";
      err.textContent = `Second opinion unavailable: ${result.cloudError}`;
      body.appendChild(err);
    }

    wrap.append(head, body);
    root.append(style, wrap);
    return host;
  };

  window.BaitWatch = BaitWatch;
})();
