# Project plan & task split

How the work was organized. For setup and architecture, see the root `README.md`.

## Phase 1 — working end-to-end build

- **Backend:** scikit-learn model (TF-IDF + Logistic Regression) trained on our own dataset, served by FastAPI (`POST /classify/`)
- **Extension:** `popup.js`, `storage.js`, `util.js`, `banner.js`, `style.css` — analyze UI, client-side history/blocklist (`chrome.storage.local`), CSV export, and the live warning banner
- Tested end-to-end in Chrome; fixed real bugs found along the way (emoji charset, duplicate history rows, sender-email tracking, popup resize stability)

## Phase 2 — hardening & polish

Split into three parallel tracks:

| Track | Focus |
|---|---|
| A — Model hardening | Stress-test the model against realistic non-templated messages, expand `dataset.csv` to cover gaps, retrain. Also evaluated (and rejected, with data) merging a large public SMS-spam corpus. |
| B — QA + polish | Full QA pass (CSV integrity, list scrolling, layout stability, banner), `style.css` polish, extension README update |
| C — Demo readiness | Cold-start clone-and-run test, root `README.md`, demo script, and pre-tested example messages (`DEMO_SCRIPT.md`, `demo-examples.txt`) |

## Engineering practices

- **Branch-based workflow:** work on a feature branch, open a pull request, review, then merge to `main` (`main` is protected against direct pushes).
- **Automated tests:** `python3 tests/run_all.py` runs 17 end-to-end checks (popup flow + live banner) in headless Chrome — run before every push. See `tests/README.md`.
- Locked architecture decisions kept the build shippable under the deadline: scikit-learn only (no heavy transformer stack), a stateless backend, and fixed API/storage contracts.
