# Chrome Web Store listing

Copy for the Web Store developer dashboard. Every claim here is checked against
the code in `extension/` — if you change what the extension does, change this
file in the same commit, because the listing and the privacy policy are what a
reviewer compares the code against.

Accuracy figures come from `python3 tests/run_all.py --no-browser`. Do not edit
them by hand; re-run the suite and copy what it prints.

---

## Name

    BaitWatch

## Short description

Store field: "Description", 132 characters maximum. This is also the manifest's
`description` field, and the two should stay identical.

    Catches scam and phishing messages as you read them. Runs entirely on your device — nothing is sent anywhere by default.

(120 characters.)

## Category

Productivity. It is not a "privacy and security" blocker or proxy; it reads text
and gives an opinion.

---

## Detailed description

> BaitWatch reads the message you are looking at and tells you, in plain
> language, whether someone is trying to scam you — and what they are actually
> after.
>
> It runs on your computer. The whole detector ships inside the extension: a
> rule engine, a URL and domain checker, and a small statistical model. There is
> no server in this project, no account, and no sign-up. By default nothing you
> read is sent anywhere.
>
> **What it catches**
>
> Requests for one-time passcodes, passwords, PINs and card details. Payment
> pressure — gift cards, crypto transfers, UPI collect-requests, redirected
> invoices. Threats of arrest or account closure. Demands for secrecy. Requests
> to install remote-access software. Links whose visible text disagrees with
> where they go, lookalike domains, and addresses spelled with characters from
> another alphabet so that "рaypal" reads as "paypal".
>
> **Where it works**
>
> Gmail, WhatsApp Web and Telegram Web are read automatically as you open
> messages; on Gmail it also reads the sender's address so you can block them in
> one click. On any other site there is a general scan that looks at anything
> shaped like a message. You can turn any of these off in Settings.
>
> Two things work anywhere: select text on a page, right-click, and choose
> "Check this text for scams"; or open the extension and press "Scan this entire
> page", which judges the page's text, every link on it, the site's own address,
> and whether it is asking for a password or a one-time code while claiming to
> be a company that does not own the domain.
>
> **What it tells you**
>
> A verdict — nothing suspicious, treat with caution, or almost certainly a scam
> — a risk score, the specific things in the message that drove it, and one
> concrete next step. Not a red border and a warning symbol: sentences a
> non-technical person can act on.
>
> **Your data**
>
> Verdict history, blocked and safe senders, and your settings are stored in
> this browser only. Nothing is uploaded. You can export your history as CSV or
> delete everything from Settings, and uninstalling removes all of it.
>
> **Optional: a second opinion from Claude**
>
> Off unless you turn it on. If you paste your own Anthropic API key into
> Settings, messages the on-device check cannot settle confidently are sent to
> Anthropic's API for a reasoned second opinion. That is the only case in which
> anything leaves your computer, it is billed to your own key, and the extension
> does nothing at all with it if you leave the setting off. See the privacy
> policy for exactly what is sent.
>
> **Accuracy, measured**
>
> Against a 3,248-message benchmark of 1,599 scams and 1,649 ordinary messages,
> the on-device layers alone raise a false alarm on 0.73% of legitimate messages
> and call a legitimate message "almost certainly a scam" 0.18% of the time. On
> the 175 curated messages representing the tactics it is built for, it misses
> 4.00%. On Hindi and Hinglish scams it misses 5.71%, with no false alarms on
> ordinary Hinglish. These are the project's own published test gates, run on
> every change; the code and the corpus are on GitHub under the MIT licence.
>
> Source: https://github.com/sreekarseera/baitwatch

### Caveats a reviewer may hold you to

- The 0.73% / 4.00% / 5.71% figures are printed by `tests/test_benchmark.mjs`
  and are for the **on-device layers only** (`analyzeLocal`), which is the
  default configuration. They are not a claim about the Claude tier.
- The benchmark corpus overlaps the model's training rows, so it is a
  regression alarm rather than an independent accuracy claim. The listing avoids
  the phrase "accuracy" for exactly that reason; `test_benchmark.mjs` documents
  the overlap. The model's own cross-validated figure — 95.85% validation
  accuracy, 6,000 terms — is shown in the extension's Settings page and is not
  used as a marketing number here.

---

## Single purpose

Chrome requires one sentence, and requires that every permission trace back to
it.

    BaitWatch analyses the text of messages and pages the user is reading and
    tells them whether it is a scam or phishing attempt.

Everything the extension does is that one job: automatic scanning on message
sites, the right-click check, the whole-page check, and the history and
sender lists that record and act on the verdicts.

---

## Permission justifications

One per permission, in the form the dashboard asks for. Each is verifiable in
the source file named.

### `storage`

Stores the user's settings, verdict history, blocked-sender list and safe-sender
list in `chrome.storage.local`, and the user's own Anthropic API key if they
choose to enable the optional Claude tier. All of it is local to the browser;
`extension/lib/storage.js` is the only file that writes it and it never contacts
a network. Nothing is written to `chrome.storage.sync`, so nothing is synced to
the user's Google account.

### `activeTab`

When the user clicks the toolbar icon and presses "Use selection" or "Scan this
entire page", the popup has to reach the content script in the tab they are
looking at. Tabs that were already open before the extension was installed or
reloaded have no content script in them, so the popup injects one on demand and
retries (`extension/popup/popup.js`, `messageActiveTab`). `activeTab` grants
that access for the tab the user just acted on, and only after they acted. The
extension does not request the `tabs` permission and never reads a tab's URL
through the tabs API — the content script reports its own `location.href` in the
page payload instead (`extension/content/scanner.js`, `collectPage`).

### `scripting`

The on-demand injection described above is a `chrome.scripting.executeScript`
call, injecting the extension's own three content-script files into the active
tab. It is the only use; nothing is injected into any tab the user has not just
acted on, and no remote or generated code is ever executed.

### `contextMenus`

Adds one item, "Check this text for scams", shown only when text is selected
(`contexts: ["selection"]`, in `extension/background/service-worker.js`). This is
how the extension reaches content its site adapters cannot read — canvas-rendered
apps, PDFs, iframes.

### `notifications`

Shows the verdict for that right-click check. The popup is not open at that
moment, so a notification is the only place the answer can go. One notification
per check, no others.

### Optional host permission: `https://api.anthropic.com/*`

Declared under `optional_host_permissions`, so it is **not** granted at
install. The options page requests it with `chrome.permissions.request()` at
the moment the user switches the Claude second opinion on, and calls
`chrome.permissions.remove()` when they switch it back off. If the user
declines, the toggle returns to off rather than promising a feature the
extension cannot deliver.

It covers exactly one endpoint, `POST /v1/messages`, called from
`extension/engine/claude.js`. The service worker re-checks the grant before
every escalation (`chrome.permissions.contains`), so a permission revoked from
`chrome://extensions` stops the feature rather than producing failed requests.

The extension holds no other host permission and contacts no other server. A
newly installed copy can reach nothing at all — `tests/run_all.py` asserts this
in a real browser by reading `chrome.permissions.getAll()` from the service
worker.

### Content scripts on `<all_urls>`

The extension has to be able to read a message wherever the user reads it. It
ships adapters for Gmail, WhatsApp Web and Telegram Web plus a deliberately
conservative generic adapter for every other site, and the user's own scam mail
does not arrive only on those three (`extension/content/adapters.js`). The
content script does DOM work only: it collects candidate message text and hands
it to the service worker for analysis. It runs in the top frame only
(`all_frames: false`), it never reads the value of any form field — the
credential check records only *which kinds* of field a page contains, never what
is typed into them (`collectCredentialFields`) — and it sends nothing to any
server. Automatic scanning on non-message sites can be switched off entirely in
Settings ("Every other site").

### Remote code

None. The extension has no build step and loads no script from any origin; the
Manifest V3 CSP is left at `script-src 'self'`. The statistical model is a JSON
file shipped inside the package (`extension/engine/model-weights.json`) and is
read from the extension's own origin, not fetched from a network.

---

## Data-use disclosures

The dashboard's "Data safety" section asks you to check the categories of user
data collected and then to affirm three statements. What follows is what is true
of this code.

**Categories to declare**

- **Personally identifiable information** — yes, in one narrow sense. Email
  addresses that appear in the message or on the page are stored locally so the
  user can block them, and are included in the CSV the user exports themselves.
  They are not transmitted anywhere.
- **Website content** — yes. The extension reads the text of messages and pages
  the user is viewing, in order to analyse them. It is stored locally as verdict
  history. It is transmitted only in the Claude case described below.
- **Authentication information** — yes, if the user opts in. The Anthropic API
  key the user pastes into Settings is stored locally and sent only to
  `api.anthropic.com` as the credential for their own request.
- Not collected: health, financial and payment information, personal
  communications beyond the message text described above, location, web history,
  and user activity. There is no analytics, no telemetry, no crash reporting and
  no unique identifier of any kind — the extension makes no network request at
  all in its default configuration.

**The three affirmations**

- *I do not sell or transfer user data to third parties outside of the approved
  use cases.* — True. The sole transfer is the user's own message text to
  Anthropic, at the user's explicit instruction and on the user's own API key.
  Anthropic is the user's chosen processor here, not a third party the extension
  sells to.
- *I do not use or transfer user data for purposes unrelated to my item's single
  purpose.* — True. The only outbound request in the codebase asks for a scam
  verdict on the message the user is checking.
- *I do not use or transfer user data to determine creditworthiness or for
  lending purposes.* — True.

**The Claude tier, stated precisely**

This is the one thing that sends data off the device, so it needs to be
described exactly rather than softened:

- It is **off by default** (`cloudTier: false` in `extension/lib/storage.js`) and
  additionally does nothing until the user has saved an API key — both
  conditions are required in `extension/background/service-worker.js`.
- The key is the **user's own** Anthropic key, entered by them in Settings and
  stored in `chrome.storage.local`. There is no key belonging to this project,
  and no server operated by it.
- When on, it does **not** run on every message. It runs only when the local
  layers were genuinely uncertain: a fused risk score between 25 and 80, or a
  non-safe verdict with no human-readable reason to show (`shouldEscalate` in
  `extension/engine/engine.js`). Measured over the project's own corpora that is
  32% of the general benchmark set and 16% of the curated scam set — call it
  between one message in three and one in six, depending on what the user reads.
- What is sent: the message text, truncated to 12,000 characters, plus the local
  risk score and the list of signals the local rules fired
  (`buildUserContent` in `extension/engine/claude.js`). Nothing else — not the
  page URL, not the sender address, not the user's history, blocklist or
  settings.
- Where it goes: `https://api.anthropic.com/v1/messages`, and nowhere else.
  Anthropic's handling of it is governed by Anthropic's own terms for API
  traffic, which apply to the user's account.
- If the request fails the extension falls back to the local verdict and shows
  the error; it never blocks on the network.

---

## Assets still needed before submission

The dashboard will not accept the listing without these, and none of them exist
in the repo yet:

- **Screenshots**: at least one, 1280×800 or 640×400. `docs/DEMO_SCRIPT.md`
  describes the flows worth capturing; `docs/demo-examples.txt` has the messages
  to paste. Screenshots must show the real UI, and the pasted text must not be a
  real person's message.
- **Small promo tile**: 440×280.
- **Privacy policy URL**: `docs/PRIVACY.md` has the text. It must be reachable at
  a public URL — the rendered GitHub page for that file is acceptable.
- **Support/homepage URL**: the GitHub repository.
