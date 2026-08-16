# Rationale: consent surface for shortener resolution + URLhaus

Context: `docs/PROGRESS.md`'s `## Next` section flags two wanted opt-in
network features — shortener resolution and a URLhaus feed check — both of
which break "nothing leaves your computer" the way the existing Claude
second-opinion tier already does, calling for one consent surface designed
once. A first attempt at this design reached some conclusions but left three
questions open; this document sanity-checks those conclusions against the
actual code and resolves the three questions rather than re-punting them.
See `mockup.html` for the resulting UI and `copy.md` for the final strings.

## Toggle structure (sanity-checked, not re-litigated)

Three independent toggles, no master switch:

| Setting | Default | Sends | To |
|---|---|---|---|
| `cloudTier` (existing) | off | message text, local risk score, local signal list | `api.anthropic.com`, fixed |
| `resolveShorteners` (new) | off | the shortened URL + requester IP | whichever of ~19 known shortener domains the link is from |
| `checkUrlhaus` (new) | off | nothing per-check; a standing feed download | `urlhaus.abuse.ch`, fixed |

I read `extension/options/options.js`, `extension/lib/storage.js`, and
`extension/manifest.json` to confirm this holds up rather than assuming it:
`cloudTier` really is implemented as a single boolean gating a single fixed
optional host permission (`https://api.anthropic.com/*`, declared in
`manifest.json`'s `optional_host_permissions` and requested/released in
`options.js` via `chrome.permissions.request`/`.remove`), and the three
features really do have three different recipients and three different
payloads. Collapsing them into one switch would make at least one of those
three claims false the moment any single one of them is off, which is exactly
the failure mode the existing `describeTier()` comment in `popup.js` calls out
for the Claude tier ("the one line in this interface that has to be literally
true"). Keeping them separate is the only structure where each toggle's
on/off state means exactly what its copy says. Confirmed, not changed.

Default state: all three off. This matches `DEFAULT_SETTINGS` in
`extension/lib/storage.js` (`cloudTier: false`) and the project's stated
default posture ("no network request at all" out of the box, per
`docs/PRIVACY.md`).

### Proposed storage keys (`extension/lib/storage.js`, not modified by this task)

```js
const DEFAULT_SETTINGS = {
  // ...existing keys...
  resolveShorteners: false,
  checkUrlhaus: false,
  urlhausAuthKey: "",        // free abuse.ch Auth-Key, same storage pattern as apiKey
};
```

The downloaded URLhaus list itself should **not** live in `settings` — it's
data, not a preference, and it can be tens of thousands of entries. It belongs
in its own top-level key, refreshed on a timer:

```js
// chrome.storage.local key "urlhausFeed"
{ updatedAt: <epoch ms>, entries: [...] }   // or an IndexedDB store, if the
                                              // feed turns out too large for
                                              // storage.local's quota
```

### Proposed permission origins (`extension/manifest.json`, not modified)

```json
"optional_host_permissions": [
  "https://api.anthropic.com/*",

  "https://bit.ly/*", "https://tinyurl.com/*", "https://goo.gl/*",
  "https://t.co/*", "https://ow.ly/*", "https://is.gd/*", "https://buff.ly/*",
  "https://rebrand.ly/*", "https://cutt.ly/*", "https://shorturl.at/*",
  "https://rb.gy/*", "https://tiny.cc/*", "https://bl.ink/*", "https://t.ly/*",
  "https://snip.ly/*", "https://s.id/*", "https://clck.ru/*", "https://u.to/*",
  "https://v.gd/*",

  "https://urlhaus.abuse.ch/*"
]
```

The shortener list is exactly the `URL_SHORTENERS` set already defined in
`extension/engine/urls.js` — reusing it means the set of domains the extension
is willing to contact matches the set it already recognises as shorteners,
with one source of truth instead of two lists drifting apart.

---

## Question 1 — first redirect hop, or the full chain?

**Resolution: first hop only. This isn't a UX compromise — it's the only
option the permission model the project already committed to can support.**

I checked how `cloudTier` actually gets its network access, because the task
asked me to rather than assume. `options.js` calls
`chrome.permissions.request({ origins: [ANTHROPIC_ORIGIN] })` where
`ANTHROPIC_ORIGIN` is a single hardcoded string, and Chrome's
`optional_host_permissions` mechanism requires every origin a call to
`permissions.request()` might ever grant to be **statically declared in the
manifest in advance**. That's not an implementation detail of this codebase —
it's a hard platform constraint. There is no API for requesting "whatever
origin this fetch happens to redirect to next"; the set of grantable origins
is fixed at package-review time and can't grow at runtime.

That constraint decides the question. A shortener's *first* redirect target is
knowable in advance in the relevant sense: it's always the shortener domain
itself (bit.ly resolves at bit.ly, tinyurl.com at tinyurl.com), so the ~19
known shortener origins above can be pre-declared and requested exactly the
way `ANTHROPIC_ORIGIN` is today. A shortener's *second* hop is not — it can be
any domain on the internet, decided by whatever the first server returns, and
there is no way to pre-declare "the domain that domain X will redirect to,"
because that isn't known until X is asked. Following the chain past the first
hop therefore has exactly two options, both bad: request `<all_urls>` (which
is precisely the grant the project's own manifest comment structure and
`docs/PRIVACY.md` are organized around not asking for, and would contradict
the "off by default, scoped access" story at the exact moment a privacy-
conscious user is deciding whether to trust the toggle), or prompt for a new
permission mid-chain on every single hop (which Chrome will not even do
outside a user gesture — `options.js`'s own comment notes
`permissions.request()` only works attached to a click or change event, and a
background redirect fetch is neither).

So: fetch each shortener URL with `redirect: "manual"` in the service worker,
read the `Location` header of that one response, and score against that
destination. If the destination is itself a recognized shortener, stop —
don't re-fetch it. This is a real, disclosed limitation (a link that chains
two shorteners together only gets unwound once), not a hidden one; the copy
in `copy.md` says so directly ("Only the first redirect is followed... a link
that hops through more than one shortener is only unwound once") rather than
letting the toggle's name overclaim.

## Question 2 — hash the URL before sending it to URLhaus?

**Resolution: the question is moot, for a fact-based reason and a design
reason that reinforce each other.**

Fact, from reading abuse.ch's own API docs and repo README
(`urlhaus-api.abuse.ch`, `github.com/abusech/URLhaus`): the URLhaus **URL**
lookup endpoint (`/v1/url/`) takes only a raw URL string, or URLhaus's own
internal numeric ID for a URL it already knows about (`/v1/urlid/`). There is
no hash-based lookup for URLs. The API does support hash lookups, but only on
a completely different endpoint (`/v1/payload/`) for a different object — the
MD5/SHA256 of a malware *file* that was downloaded from a URL, not the URL
itself. Hashing the URL client-side and sending the hash isn't an option
URLhaus's live query API offers; there's nothing on the other end that would
accept it.

Design reason, which is why I didn't stop at "not supported, use the raw
endpoint": abuse.ch made Auth-Key authentication mandatory across their
platforms as of 30 June 2025 (confirmed via multiple independent reports,
including an open `elastic/beats` issue about integrations breaking because
of it). A live per-URL query today is not an anonymous request — it's
attached to a personal Auth-Key tied to an OAuth-linked account. Even if
hash-based URL lookup existed, hashing would only hide the URL from network
eavesdroppers (HTTPS already does that); it would do nothing to hide *which
authenticated user* asked about *which URL* from abuse.ch itself, since the
Auth-Key identifies the requester on every call regardless of what's in the
request body.

Given that, the better design isn't "query live, hashed" — it's what
`docs/PROGRESS.md` already called this feature: a **feed**. Download abuse.ch's
plain-text URLhaus list (updated every 5 minutes, one malicious URL per line)
on a timer, using the Auth-Key that download requires, and check candidate
URLs against that local cached copy instead of asking abuse.ch about each one
individually. This sends *strictly less* than a hashed live query would: not
a hash of the URL under review, not even an indication that a review is
happening — only "this Auth-Key downloaded the standard feed," on the same
schedule every other user of the feed is on, decoupled from any message the
user has looked at. It also sidesteps needing to keep a network connection
alive during message scoring at all.

One caveat I want to be explicit about rather than quietly assume past: I
could not independently confirm from abuse.ch's own pages whether the
Auth-Key requirement (definitely mandatory for the live query API) also
covers the plain-text feed downloads specifically — their downloads page
returned an HTTP 403 to an automated fetch, and their FAQ page didn't address
it. Every secondary source I found describes the mid-2025 change as applying
to "all abuse.ch APIs" without carving out feed downloads as an exception, and
their auth.abuse.ch account system is shared across URLhaus/MalwareBazaar/
ThreatFox, so I'm designing on the assumption that it does apply and that the
Auth-Key field in `copy.md`/`mockup.html` is required, not optional. If a
future implementer verifies the feed is actually still anonymous, the
Auth-Key field can be dropped without changing anything else about this
design — the "download a feed, match locally" architecture is the right call
either way, independent of whether the download itself happens to need a key.

## Question 3 — extending `describeTier()` and the footer

**Resolution: `checkUrlhaus` needs no per-result change; `resolveShorteners`
does. They're not symmetric, and treating them as if they were would either
overclaim or underclaim depending on which way you erred.**

`describeTier()` in `extension/popup/popup.js` exists to answer one question
truthfully for one specific result: did anything about *this message* leave
the device while it was being checked. `checkUrlhaus`, designed as a feed
match against a local cache (Question 2), never makes a network call as part
of scoring any individual message — the call happens on a refresh timer,
unrelated to what's being scored at that moment. So a result checked with
`checkUrlhaus` on can still truthfully say "nothing left your computer" *at
the per-result level*, the same way the on-device model saying nothing
network-related about itself doesn't require a disclosure every time it
votes. `resolveShorteners` is the opposite: when a message actually contains
a shortener link and the toggle is on, a request to that shortener's domain
is part of producing *this specific* result, so the sentence becomes false
for that result specifically if it isn't updated.

Draft (extends the existing function; unchanged branches omitted for
brevity — full context in `copy.md`):

```js
function describeTier(result) {
  const shortenerNote = result.shortenerResolved
    ? " To see where a shortened link led, this check also contacted the shortening service directly."
    : "";

  if (result.tier === "claude") {
    return "Checked on your device, then confirmed with Claude." + shortenerNote;
  }
  if (result.tier === "cloud-failed") {
    const base = result.cloudReached
      ? "Checked on your device. This message was sent to Claude, which answered with an error instead of a verdict."
      : "Checked on your device. Claude could not be reached, so this message may have left your computer.";
    return base + shortenerNote;
  }
  if (result.shortenerResolved) {
    return "Checked on your device. To see where a shortened link led, this check also contacted the shortening service directly — nothing else left your computer.";
  }
  return "Checked entirely on your device — nothing left your computer.";
}
```

This requires the analyzer to attach `shortenerResolved: boolean` to the
result — a small, single-flag addition to whatever object
`extension/engine/engine.js` already builds, parallel to how `tier` and
`cloudReached` are attached today.

`renderFooter()` currently collapses everything to a boolean ("On-device
only" vs. "Claude second opinion on"), which stops being sufficient at three
independent toggles. Draft:

```js
async function renderFooter() {
  const settings = await getSettings();
  const parts = [settings.autoScan ? "Auto-scan on" : "Auto-scan off"];

  const network = [];
  if (settings.cloudTier && settings.apiKey) network.push("Claude second opinion on");
  if (settings.resolveShorteners) network.push("Shortened-link lookup on");
  if (settings.checkUrlhaus && settings.urlhausAuthKey) {
    network.push(urlhausSyncedAt ? `URLhaus list synced ${relativeTime(urlhausSyncedAt)}` : "URLhaus list syncing…");
  }

  parts.push(network.length ? network.join(" · ") : "On-device only");
  $("footer").textContent = parts.join(" · ");
}
```

(`relativeTime` and reading the sync timestamp out of the new `urlhausFeed`
storage key are implementation details for whoever wires this up — flagged
here so the footer's claim about the feed being fresh is also something that
can be literally true, not just plausible.)

---

## Non-goals of this task (per instructions)

No file under `extension/` was modified. No shortener or URLhaus network
calls were implemented. Nothing here was merged into `main` or pushed — this
document and its siblings live only on `wip/network-consent-design`.
