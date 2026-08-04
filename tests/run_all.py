"""Run the full BaitWatch V2 test suite.

Three layers, cheapest first:

  1. Model parity   — the JS re-implementation still matches scikit-learn.
  2. Engine         — 61 behavioural checks on scams, legitimate mail, URLs.
  3. Browser smoke  — the extension actually loads in Chrome, the service
                      worker starts clean, and a scam on a real page gets a
                      warning injected into the DOM.

Layers 1-2 need only Python + Node. Layer 3 additionally needs Chrome and
`pip install websocket-client`; it is skipped with a clear message if either
is missing, rather than failing the run.

    python3 tests/run_all.py
    python3 tests/run_all.py --no-browser
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.join(REPO, "tests")
EXTENSION = os.path.join(REPO, "extension")

CHROME = os.environ.get(
    "CHROME_BIN", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)
CDP_PORT = 9223
PAGES_PORT = 8791

GREEN, RED, YELLOW, DIM, RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def header(text):
    print(f"\n{text}\n{'-' * len(text)}")


def run_step(name, argv, cwd=None):
    header(name)
    result = subprocess.run(argv, cwd=cwd or REPO)
    ok = result.returncode == 0
    print(f"{GREEN if ok else RED}{'PASS' if ok else 'FAIL'}{RESET}  {name}")
    return ok


# --------------------------------------------------------------------------- #
#  Layer 3: real Chrome
# --------------------------------------------------------------------------- #

SCAM_PAGE = """<!doctype html>
<html><body>
<article>
Hi, this is your CEO. I'm in a meeting and need you to buy $500 in Apple gift
cards urgently. Send me the codes and please don't discuss this with anyone.
</article>
</body></html>
"""

CLEAN_PAGE = """<!doctype html>
<html><body>
<article>
Hi Priya, can we move tomorrow's sync to 2:30 PM? I have a conflict at 1.
Let me know if that works for you.
</article>
</body></html>
"""

# Visible text is deliberately innocuous — the only signal is the link target.
# This is what a real credential-harvest page looks like, and it is exactly
# what a text-only scan misses.
PHISH_PAGE = """<!doctype html>
<html><head><title>Sign in</title></head><body>
<h1>Sign in to continue</h1>
<p>Enter your details below to access your account.</p>
<form action="https://paypa1-secure.com/submit">
  <input name="email"><input name="password" type="password">
  <a href="https://paypa1-secure.com/login">Continue</a>
</form>
<footer>Need help? Contact SUPPORT@paypa1-secure.com
  or <a href="mailto:billing@paypa1-secure.com">billing</a>.</footer>
</body></html>
"""


def wait_for_cdp(timeout=25):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://localhost:{CDP_PORT}/json/version", timeout=1) as r:
                return json.load(r)["webSocketDebuggerUrl"]
        except (urllib.error.URLError, OSError, KeyError):
            time.sleep(0.3)
    return None


def browser_smoke():
    header("Browser smoke test")

    try:
        import websocket  # noqa: F401
    except ImportError:
        print(f"{YELLOW}SKIP{RESET}  websocket-client not installed "
              f"({DIM}pip install websocket-client{RESET})")
        return None

    if not os.path.exists(CHROME):
        print(f"{YELLOW}SKIP{RESET}  Chrome not found at {CHROME} "
              f"({DIM}set CHROME_BIN{RESET})")
        return None

    sys.path.insert(0, TESTS)
    from cdp import CDP, attach, evaluate  # noqa: E402

    pages_dir = tempfile.mkdtemp(prefix="baitwatch-pages-")
    with open(os.path.join(pages_dir, "scam.html"), "w", encoding="utf-8") as f:
        f.write(SCAM_PAGE)
    with open(os.path.join(pages_dir, "clean.html"), "w", encoding="utf-8") as f:
        f.write(CLEAN_PAGE)
    with open(os.path.join(pages_dir, "phish.html"), "w", encoding="utf-8") as f:
        f.write(PHISH_PAGE)

    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(PAGES_PORT), "--bind", "127.0.0.1"],
        cwd=pages_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    profile = tempfile.mkdtemp(prefix="baitwatch-profile-")
    chrome_log = open(os.path.join(profile, "chrome.log"), "w+", encoding="utf-8")
    chrome = subprocess.Popen(
        [
            CHROME,
            f"--remote-debugging-port={CDP_PORT}",
            f"--user-data-dir={profile}",
            f"--disable-extensions-except={EXTENSION}",
            f"--load-extension={EXTENSION}",
            # Chrome 137+ gates these switches behind a feature flag; harmless
            # on builds that never restricted them.
            "--disable-features=DisableLoadExtensionCommandLineSwitch",
            "--headless=new",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-timer-throttling",
            "--enable-logging=stderr",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=chrome_log,
    )

    passed, failed = 0, []

    def check(name, condition, detail=""):
        nonlocal passed
        if condition:
            passed += 1
            print(f"  {GREEN}PASS{RESET} {name}")
        else:
            failed.append(f"{name}{f' - {detail}' if detail else ''}")
            print(f"  {RED}FAIL{RESET} {name}{f' {DIM}- {detail}{RESET}' if detail else ''}")

    cdp = None
    try:
        ws_url = wait_for_cdp()
        if not ws_url:
            print(f"{RED}FAIL{RESET}  Chrome never exposed a debugging port")
            return False

        cdp = CDP(ws_url)
        cdp.cmd("Target.setDiscoverTargets", {"discover": True})

        # The MV3 service worker registers a moment after launch. Match on our
        # own worker path — headless Chrome ships component extensions that
        # also register service workers, and attaching to one of those makes
        # every later assertion fail for the wrong reason.
        worker = None
        for _ in range(40):
            targets = cdp.cmd("Target.getTargets")["targetInfos"]
            worker = next(
                (t for t in targets
                 if t["type"] == "service_worker"
                 and t["url"].startswith("chrome-extension://")
                 and t["url"].endswith("background/service-worker.js")),
                None,
            )
            if worker:
                break
            time.sleep(0.25)

        if not worker:
            # Branded Google Chrome builds (137+) refuse --load-extension
            # outright. That's a limitation of the browser binary, not a
            # failure of the extension, so report it as a skip with the fix.
            chrome_log.flush()
            chrome_log.seek(0)
            log_text = chrome_log.read()
            if "not allowed in Google Chrome" in log_text:
                print(f"{YELLOW}SKIP{RESET}  this Chrome build refuses --load-extension.")
                print(f"{DIM}      Branded Google Chrome 137+ blocks it. Use Chrome for Testing:")
                print(f"        npx @puppeteer/browsers install chrome@stable")
                print(f"        CHROME_BIN=<path to chrome-for-testing> python3 tests/run_all.py{RESET}")
                return None
            check("extension service worker registers", False, "no service_worker target appeared")
            return False

        check("extension service worker registers", True)

        sw_session = attach(cdp, worker["targetId"])
        # Without Runtime.enable the attached worker has no execution context
        # exposed, and every evaluate() sees `chrome` as undefined.
        cdp.cmd("Runtime.enable", session_id=sw_session)

        # NOTE: the engine cannot be exercised here via dynamic import() —
        # the HTML spec forbids it inside a ServiceWorkerGlobalScope (the
        # worker's own static imports are fine). So the engine is verified
        # through the path it actually runs in production: content script ->
        # sendMessage -> worker -> storage.
        # The extension API bindings are injected into the worker's context a
        # beat after Runtime.enable exposes it, so poll rather than assume.
        manifest_version = None
        for _ in range(20):
            manifest_version = evaluate(
                cdp, sw_session,
                "(self.chrome && chrome.runtime) ? chrome.runtime.getManifest().version : null",
            )
            if manifest_version:
                break
            time.sleep(0.25)
        check("service worker has extension APIs", manifest_version == "2.0.0",
              f"getManifest().version = {manifest_version!r}")

        # Content script: warning must appear on a scam page and not on a clean one.
        page = cdp.cmd("Target.createTarget", {"url": f"http://127.0.0.1:{PAGES_PORT}/scam.html"})
        page_session = attach(cdp, page["targetId"])
        cdp.cmd("Runtime.enable", session_id=page_session)

        warning_count = 0
        for _ in range(40):
            warning_count = evaluate(
                cdp, page_session, "document.querySelectorAll('.baitwatch-warning').length"
            ) or 0
            if warning_count:
                break
            time.sleep(0.25)
        check("warning injected on a scam page", warning_count > 0,
              "no .baitwatch-warning element after 10s")

        # Read back what the worker actually stored. This is the assertion that
        # proves the full round trip ran and that model-weights.json loaded
        # under MV3's CSP — a rules-only verdict would carry no model terms.
        raw = evaluate(
            cdp,
            sw_session,
            "chrome.storage.local.get('history').then(r => JSON.stringify(r.history || []))",
            await_promise=True,
        )
        history = json.loads(raw) if raw else []
        entry = history[-1] if history else {}
        check("worker recorded the scan", bool(entry), "history is empty")
        check("scam scored as dangerous in-browser", entry.get("verdict") == "dangerous",
              f"verdict={entry.get('verdict')} score={entry.get('score')}")
        check("verdict carries human-readable reasons", len(entry.get("reasons") or []) > 0,
              f"reasons={entry.get('reasons')}")

        clean = cdp.cmd("Target.createTarget", {"url": f"http://127.0.0.1:{PAGES_PORT}/clean.html"})
        clean_session = attach(cdp, clean["targetId"])
        cdp.cmd("Runtime.enable", session_id=clean_session)
        time.sleep(3)
        clean_warnings = evaluate(
            cdp, clean_session, "document.querySelectorAll('.baitwatch-warning').length"
        ) or 0
        check("no warning on an ordinary page", clean_warnings == 0,
              f"{clean_warnings} false positive warning(s)")

        # Whole-page scan: drive the same path the popup's "Scan this entire
        # page" button uses — COLLECT_PAGE in the tab, then ANALYZE in the
        # worker. The fixture's visible text is harmless; all the danger is in
        # the href and the form action.
        #
        # This runs in the extension's own popup page, not the service worker:
        # a worker cannot chrome.runtime.sendMessage to itself, so driving it
        # from there fails with "Receiving end does not exist".
        cdp.cmd("Target.createTarget",
                {"url": f"http://127.0.0.1:{PAGES_PORT}/phish.html"})
        time.sleep(1.5)

        ext_id = worker["url"].split("/")[2]
        popup = cdp.cmd("Target.createTarget",
                        {"url": f"chrome-extension://{ext_id}/popup/popup.html"})
        popup_session = attach(cdp, popup["targetId"])
        cdp.cmd("Runtime.enable", session_id=popup_session)
        time.sleep(1)

        scan = evaluate(
            cdp,
            popup_session,
            """(async () => {
                 // No "tabs" permission, so tab.url is undefined and we cannot
                 // filter by URL — ask every tab and keep the one that reports
                 // itself as the phishing fixture.
                 const tabs = await chrome.tabs.query({});
                 let page = null;
                 for (const t of tabs) {
                   try {
                     const p = await chrome.tabs.sendMessage(t.id, {type: 'COLLECT_PAGE'});
                     if (p && p.url && p.url.includes('phish.html')) { page = p; break; }
                   } catch { /* no content script on this tab */ }
                 }
                 if (!page) return JSON.stringify({error: 'phish tab not found'});

                 const r = await chrome.runtime.sendMessage({
                   type: 'ANALYZE', text: page.text,
                   sender: (page.emails || [])[0] || '',
                   extraUrls: page.extraUrls, source: 'page',
                 });
                 return JSON.stringify({
                   links: page.extraUrls.length,
                   hasFormAction: page.extraUrls.some(u => u.includes('/submit')),
                   reportsOwnUrl: Boolean(page.url),
                   emails: page.emails || [],
                   senderRecorded: r.sender,
                   verdict: r.verdict, score: r.score,
                   ids: r.reasons.map(x => x.id),
                 });
               })()""",
            await_promise=True,
        )
        scanned = json.loads(scan) if scan else {}

        check("content script returns page text + link targets",
              scanned.get("links", 0) >= 3, f"got {scanned}")
        check("form action is collected, not just anchors",
              scanned.get("hasFormAction") is True, f"got {scanned}")
        check("content script reports its own URL (no tabs permission needed)",
              scanned.get("reportsOwnUrl") is True, f"got {scanned}")
        check("whole-page scan catches a fake sign-in page",
              scanned.get("verdict") not in (None, "safe"), f"got {scanned}")
        check("it catches it via the link target, not the text",
              "lookalike_domain" in (scanned.get("ids") or []), f"reasons: {scanned.get('ids')}")

        emails = scanned.get("emails") or []
        check("addresses on the page are collected and lowercased",
              "support@paypa1-secure.com" in emails, f"emails: {emails}")
        check("mailto: links are collected too",
              "billing@paypa1-secure.com" in emails, f"emails: {emails}")
        check("the sender reaches the verdict and history",
              scanned.get("senderRecorded") == "support@paypa1-secure.com",
              f"sender recorded as {scanned.get('senderRecorded')!r}")

        # NOTE: the popup's on-demand content-script injection is deliberately
        # not asserted here. It relies on the `activeTab` permission, which
        # Chrome grants only when the user actually invokes the extension
        # (clicking the toolbar icon). This test opens popup.html as an
        # ordinary tab, so that grant never happens and executeScript fails
        # with "Extension manifest must request permission to access the
        # respective host" — a limitation of the harness, not of the feature.
        # The re-entry guard it depends on lives at the top of
        # content/scanner.js (window.__baitwatchScannerLoaded).

    finally:
        if cdp:
            try:
                cdp.close()
            except Exception:
                pass
        chrome_log.close()
        chrome.terminate()
        server.terminate()
        try:
            chrome.wait(timeout=5)
        except subprocess.TimeoutExpired:
            chrome.kill()
        shutil.rmtree(profile, ignore_errors=True)
        shutil.rmtree(pages_dir, ignore_errors=True)

    ok = not failed
    print(f"{GREEN if ok else RED}{'PASS' if ok else 'FAIL'}{RESET}  "
          f"Browser smoke test ({passed} checks)")
    return ok


# --------------------------------------------------------------------------- #

def main():
    results = []

    results.append(("Model parity (JS vs scikit-learn)",
                    run_step("Model parity (JS vs scikit-learn)",
                             [sys.executable, os.path.join(TESTS, "test_parity.py")])))

    results.append(("Detection engine",
                    run_step("Detection engine",
                             ["node", os.path.join(TESTS, "test_engine.mjs")])))

    if "--no-browser" not in sys.argv:
        browser = browser_smoke()
        if browser is not None:
            results.append(("Browser smoke test", browser))

    header("Summary")
    for name, ok in results:
        print(f"  {GREEN + 'PASS' + RESET if ok else RED + 'FAIL' + RESET}  {name}")

    failed = [name for name, ok in results if not ok]
    if failed:
        print(f"\n{RED}{len(failed)} suite(s) failed.{RESET}")
        return 1
    print(f"\n{GREEN}All suites passed.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
