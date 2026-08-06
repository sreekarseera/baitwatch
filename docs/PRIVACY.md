# BaitWatch privacy policy

Last updated: 6 August 2026. Applies to BaitWatch version 2.0.0.

BaitWatch is an open-source browser extension that reads messages you are
already looking at and tells you whether they look like a scam. This document
describes what it reads, what it keeps, and the one situation in which anything
leaves your computer. It describes the code in this repository, which you can
read yourself: every claim below names the file that implements it.

There is no server in this project. Nobody operates a BaitWatch backend, there
is no account to create, and the extension has no way to report anything to its
authors. In its default configuration it makes no network request at all.

## Who is responsible

The BaitWatch project, https://github.com/sreekarseera/baitwatch. Questions and
corrections go in that repository's issue tracker.

## What the extension reads

**Message text on sites it has an adapter for.** When automatic scanning is on,
the extension reads the body text of open emails on Gmail and of incoming
messages on WhatsApp Web and Telegram Web. On Gmail it also reads the sender's
address, so that "block this sender" has something to act on. On WhatsApp and
Telegram it reads incoming messages only and never what you send
(`extension/content/adapters.js`).

**Anything shaped like a message on other sites.** A generic adapter looks at
elements that read like a message — articles, list items, quoted blocks — on
sites with no dedicated adapter. This is the noisiest of the four and can be
turned off on its own in Settings, under "Every other site".

**Text you select, when you ask.** Selecting text, right-clicking and choosing
"Check this text for scams" sends that selection to the analyser. The same text
can be pulled into the popup with "Use selection".

**A whole page, when you ask.** Pressing "Scan this entire page" collects, from
the tab you are looking at (`collectPage` in `extension/content/scanner.js`):

- the page's visible text, truncated to 20,000 characters;
- the destination of up to 200 links, and the `action` targets of any forms;
- the page's own address and its title;
- email addresses appearing in the text or in `mailto:` links, capped at 20;
- **which kinds** of credential field the page contains — whether there is a
  password box or a one-time-code box. Only the kind. The extension never reads
  the value of any input, on this or any other path.

**Nothing else.** The extension does not read cookies, browsing history, form
values, keystrokes, files, or any tab other than the one you acted on. It does
not request the `tabs` permission and cannot enumerate your open tabs; when it
needs to know what page it is on, the content script reports its own address.

## What is stored, and where

Everything is stored in `chrome.storage.local`, which lives in your browser
profile on your computer. Nothing is written to `chrome.storage.sync`, so
nothing is copied to your Google account or to your other devices. The only
file that writes any of it is `extension/lib/storage.js`.

| Key | What it holds |
|---|---|
| `history` | One record per message checked: the message text, the sender address if known, the verdict, the risk score, the explanation and reasons shown to you, whether the verdict came from the on-device layers or from Claude, where it was found, and a timestamp. Page scans store only the first 1,000 characters of the page. Records are deduplicated on text and sender, and the list is capped at the 500 most recent. |
| `blocklist` | Email addresses or numbers you pressed "Block" on, lowercased. |
| `allowlist` | Senders you marked as safe, lowercased. |
| `settings` | Your toggles — automatic scanning, which sites, how severe a verdict has to be before you are warned, the history cap — and, if you enabled the optional Claude tier, your Anthropic API key. |
| `stats` | Three counters: messages checked, messages flagged, and Claude requests attempted. Numbers only. Failed requests are counted too, so this is a complete record of how often your text was sent for a second opinion. |

Two consequences worth being explicit about, because they follow from the design
rather than from any promise:

- **History contains the messages themselves.** If a scam message quoted your
  bank balance, that text is in local storage until you clear it or it falls off
  the 500-record end. Anyone with access to your browser profile can read it.
  You can wipe it at any time from the popup's History tab or Settings.
- **The API key is stored as you typed it.** `chrome.storage.local` is not
  encrypted, and the extension does not encrypt it either — there is no key to
  encrypt it with that would not also be sitting on the same disk. It is
  protected by your operating system account and your browser profile, and by
  nothing else. Treat it the way you would treat a key in a config file, and
  remove it from Settings if you stop using the feature.

## What never leaves your computer

In the default configuration — the Claude second opinion switched off, which is
how the extension installs — nothing does. The detector ships inside the
extension: a rule engine, a URL and domain checker, and a statistical model
stored as a JSON file in the package. Analysis runs in the extension's service
worker on your machine (`extension/background/service-worker.js`). Your history,
blocklist, allowlist, settings, counters and API key are never transmitted
anywhere under any setting.

There is no analytics, no telemetry, no error reporting, no advertising, no
tracking identifier, and no unique installation ID. The extension does not sell
or share any data, because it does not have anywhere to send it.

## The one exception: the Claude second opinion

The extension can ask Anthropic's Claude for a reasoned second opinion on
messages the on-device layers cannot settle. This is the only feature that
transmits anything, and this section is the reason this document exists.

**It is off unless you turn it on.** The setting ships as `cloudTier: false`. In
addition, it does nothing until you have saved an Anthropic API key: both the
toggle and a saved key are required before any request is made
(`extension/background/service-worker.js`).

**It uses your API key, not ours.** You create the key at
console.anthropic.com, paste it into Settings, and Anthropic bills your account
for the requests. This project has no key and no account of its own.

**It does not run on every message.** Requests are made only when the local
layers were genuinely uncertain — a fused risk score between 25 and 80, or a
non-safe verdict with no human-readable reason to show you (`shouldEscalate` in
`extension/engine/engine.js`). Measured across this project's own test corpora,
that is 32% of a general message set and 16% of the curated scam set. A message
from a sender on your safe list is never analysed at all, and a message from a
sender you blocked is judged from the blocklist without reaching the analyser,
so neither is ever sent.

**What is sent.** One HTTPS request to `https://api.anthropic.com/v1/messages`
containing: the text of the message being checked, truncated to 12,000
characters; the risk score the local rules produced; and the list of signals
those rules fired. That is the whole payload — see `buildUserContent` in
`extension/engine/claude.js`. It does not include the page's address, the sender
address, your history, your blocklist or allowlist, your settings, or any
identifier for you or for your browser.

**One further request.** Pressing "Test" next to the API key field in Settings
sends a single one-token request to the same endpoint, containing the word "hi"
and nothing else, purely to confirm the key works (`verifyApiKey`). It is the
only outbound request that can happen while the second-opinion toggle is off,
and it happens only when you press that button.

**What happens at the other end.** The request goes to Anthropic and to no one
else. Anthropic's handling of it is governed by the terms and privacy policy
attached to your own API account, at https://www.anthropic.com/legal — this
extension cannot and does not change them. If the request fails, the extension
falls back to the local verdict and shows you the error; it never waits on the
network to give you an answer.

**Turning it off.** Unchecking the setting stops all requests immediately.
Clearing the API key field also stops them, and removes the key from storage.

## Your control over what is stored

- **See it.** The popup's History tab lists every verdict, and the Senders tab
  lists both sender lists.
- **Export it.** "Export CSV" in the History tab and "Export blocklist" in the
  Senders tab write a file to your downloads folder. This is a local file
  operation; nothing is uploaded.
- **Delete it.** "Clear" in the History tab empties the history. "Delete
  everything stored by this extension" in Settings clears all of the above,
  including your API key, in one action.
- **Uninstall.** Removing the extension deletes its `chrome.storage.local` data
  with it. Nothing survives elsewhere, because there is nowhere else.

## Children

The extension is not directed at children and collects nothing from anyone,
including them.

## Changes to this policy

This file is versioned in the repository alongside the code it describes, so
every change to it is visible in the git history. If a future version of the
extension transmits anything it does not transmit today, this document changes
in the same commit and the date at the top moves.
