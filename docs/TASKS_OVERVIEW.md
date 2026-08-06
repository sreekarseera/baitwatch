# Project plan & task split — V1 hackathon, archived

> **This is a historical document. It does not describe the current code.**
>
> It records how the original hackathon build was organized, in the state it was
> in when the hackathon ended. Everything below refers to **V1**, which had a
> FastAPI backend, a single classifier, and a 17-check end-to-end suite. None of
> that exists in this repository any more: V2 removed the backend entirely,
> detection runs in the browser, and the test suite is a different thing
> measuring different properties.
>
> Nothing here should be used as instructions. Read it only if you want to know
> how the work was divided at the time.
>
> - How the extension works today → the root [`README.md`](../README.md)
> - What changed and what is next → [`PROGRESS.md`](PROGRESS.md)

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

## Engineering practices at the time

- **Branch-based workflow:** work on a feature branch, open a pull request, review, then merge to `main` (`main` was protected against direct pushes).
- **Automated tests:** `python3 tests/run_all.py` ran 17 end-to-end checks (popup flow + live banner) in headless Chrome, before every push. The file still exists and still carries that name, but it now runs five entirely different suites — see [`tests/README.md`](../tests/README.md).
- Locked architecture decisions kept the build shippable under the deadline: scikit-learn only (no heavy transformer stack), a stateless backend, and fixed API/storage contracts.

## Why V2 is not this

The backend was the deadline decision that aged worst. A local classifier
served over HTTP meant an install was a clone, a virtualenv, a `pip install`
and a running `uvicorn` process — for a tool whose whole audience is people who
do not run servers. It also meant every message a user scanned crossed a network
boundary, which is a promise no scam detector should have to break. V2 exports
the same model to JSON and runs inference in the extension itself, which is why
the backend, the API contract, and this task split all went away together.
