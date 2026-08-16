# Copy: Network features consent surface

Final UI text for the two new opt-in network features, written in the voice of
the existing "Second opinion from Claude" section in
`extension/options/options.html` — plain, specific about what leaves the
device and to whom, and honest about the limits of what's on offer. See
`mockup.html` for these in place and `rationale.md` for the reasoning behind
the wording choices (especially "first redirect only" and "downloads a list"
rather than "looks it up").

Section header changes from **"Second opinion from Claude"** to **"Network
features"**, with the Claude toggle becoming the first of three subsections
under it rather than its own top-level section. Copy for the Claude subsection
is unchanged from what ships today; it's included in the mockup for
continuity but isn't reproduced again below.

---

## Section intro (replaces the old Claude-only `.note`)

> Everything below is off by default and stays off until you turn it on. Each
> toggle here sends something different to a different place — one message's
> text to Anthropic, one link to whichever service shortened it, or nothing at
> all beyond a standing download from abuse.ch — so each has its own switch
> and its own permission. Turning one on never turns on another, and turning
> any of them off hands back the network access it used.

---

## 1. Resolve shortened links (`resolveShorteners`)

**Subsection note:**

> When on, and a message contains a link from a known shortening service —
> bit.ly, tinyurl.com, and 17 others BaitWatch already recognises — the
> extension asks that service directly where the link leads, before scoring
> it. That tells the shortening service which link you're looking at, and
> shows it your computer's IP address. Nothing else about the message goes
> anywhere. Only the *first* redirect is followed, never the pages after it,
> so a link that hops through more than one shortener is only unwound once.

**Toggle:**

- Label: **Look up where shortened links actually go**
- Sub-label: *Only for links from known shortening services — full list in
  Settings → About.*

**Permission-denial message** (mirrors `cloudTier`'s pattern in `options.js`):

> Looking up shortened links needs permission to reach the shortening
> services themselves. Without it nothing can be sent, so the feature stays
> off.

**Permission-revoked message** (mirrors the `hasNetworkPermission()` check
already run for `cloudTier` on load):

> Permission to reach shortening services was revoked, so this can't run.
> Switch it off and on again to restore it.

**Turned-off confirmation:**

> Shortened-link lookup off. Network access to shortening services revoked.

---

## 2. Check links against URLhaus (`checkUrlhaus`)

**Subsection note:**

> When on, the extension periodically downloads abuse.ch's public URLhaus
> list of known malicious web addresses using your own free Auth-Key, and
> keeps a copy on this device. A link in a message you're checking is
> compared against that local copy — the link itself is never sent to
> abuse.ch or anyone else. The only thing abuse.ch sees is that this Auth-Key
> downloaded their standard list, on the same schedule as every other user of
> it, unconnected to any message you've looked at.

**Toggle:**

- Label: **Check links against URLhaus's malicious-link list**
- Sub-label: *Downloads a public threat list from abuse.ch; the links you
  check stay on your device.*

**Auth-Key field** (mirrors the `apiKey` field):

- Label: **abuse.ch Auth-Key**
- Placeholder: `Auth-Key…`
- Hint: *Free at `auth.abuse.ch` — sign in with Google, GitHub, or similar,
  then generate an Auth-Key under "Optional". abuse.ch requires this of every
  user as of mid-2025; BaitWatch has no key of its own to share. Stored only
  in this browser.*

**Turning it on without a key** (mirrors the `cloudTier`/`apiKey` empty-key
message):

> Add your abuse.ch Auth-Key below to enable this.

**Sync status line** (new — there's no equivalent on `cloudTier` because that
feature has no standing background job; this one does):

- Before first download: *Not yet downloaded.*
- After a successful refresh: *List last updated `{relative time}` — `{N}`
  entries.*
- On a failed refresh: *Couldn't refresh the URLhaus list ({reason}). Using
  the copy from `{relative time}`.* — or, if there is no earlier successful
  copy yet: *Couldn't download the URLhaus list yet ({reason}). Links aren't
  being checked against it until this succeeds.*
- On an invalid/rejected key: *abuse.ch rejected this Auth-Key. Check that
  you copied it correctly from auth.abuse.ch.*

**Turned-off confirmation:**

> URLhaus check off. Network access to urlhaus.abuse.ch revoked, and the
> downloaded list has been deleted.

---

## Footer / popup disclosure text

`extension/popup/popup.js` has two places that currently only know about
`cloudTier`: `describeTier()` (per-result, in the result card) and
`renderFooter()` (a one-line summary at the bottom of the popup). Both need to
stay literally true now that a result can also involve a shortener lookup, per
`tests/test_engine.mjs`'s "a failed cloud call must not claim privacy" block.
Full reasoning and draft code are in `rationale.md`; the resulting strings
are:

**`describeTier()`, on-device tier, shortener was resolved this check:**

> Checked on your device. To see where a shortened link led, this check also
> contacted the shortening service directly — nothing else left your
> computer.

**`describeTier()`, Claude tier, shortener was resolved this check:**

> Checked on your device, then confirmed with Claude. This check also
> contacted a shortening service to see where a shortened link led.

**`renderFooter()`**, replacing the single "On-device only" / "Claude second
opinion on" line with a joined list of whatever is actually on:

> `Auto-scan on · Claude second opinion on · Shortened-link lookup on ·
> URLhaus list synced 2h ago`

> `Auto-scan on · On-device only` (all three network features off — wording
> unchanged from today)

No new copy is needed in `describeTier()` for `checkUrlhaus` itself: because
it's checked against a locally cached list rather than queried live, no
network call happens *while a specific message is being scored*, so the
per-result "nothing left your computer" line stays true whether or not
`checkUrlhaus` is on. It only shows up in the footer, because the extension
as a whole does make standing network calls once it's on, even though no
single check does.
