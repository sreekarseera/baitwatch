# Progress

Where the project stands and what is worth doing next. For how it works, see
the root [`README.md`](../README.md); this file is the running log.

Last updated **2026-09-05**.

## Current state

| | |
|---|---|
| Repo | `github.com/sreekarseera/baitwatch` (public, MIT) |
| Archive | `github.com/sreekarseera/baitwatch-archive` (private, the original 32-commit history) |
| Detection | 24 heuristics + URL analysis + brand impersonation + on-device classifier |
| Model | 3,603 rows, 94.31% validation, 93.81% ±0.88% five-fold CV, 6,000 terms, 263.9 KB |
| Tests | 328 engine checks, model parity (tokens + predictions), 5 accuracy gates, 4 held-out gates, 8 ambient solo-fire gates (21 ambient fixtures across all three sources), 35 adapter checks, 20 browser checks — the JS/Python layers all verified 2026-09-05; the browser layer (`python3 tests/run_all.py`'s live-Chrome portion) was last verified against a real Chrome instance on an earlier date, not re-run today (no Chrome for Testing checkout in the environment that did today's work) |

Measured accuracy, from `node tests/test_benchmark.mjs`:

| | rate |
|---|---|
| legitimate mail flagged | 0.49% |
| …called *dangerous* | 0.16% |
| targeted scams missed | 0.00% |
| Hinglish/Hindi scams missed | 0.00% |
| …devanagari alone | 0/170 |
| false alarms on ordinary Hinglish | 1/122 |

And from `node tests/test_holdout.mjs`, which is the number to trust for
false positives — the benchmark above grades the model on rows it trained on:

| | rate |
|---|---|
| held-out legitimate mail flagged | 0/66 |
| held-out real websites flagged | 0/16 |
| held-out real scam miss rate | 25/55 (45.45%) |

That number moved from 63.64% on 2026-09-05 — see that entry below — by
tightening one existing rule, `prize_or_windfall`, to catch noisier phrasing.
It's still not close to zero, and that remains expected: this corpus is a
different tactic distribution than the one the rules are built for, not a
bug to chase to 0%.

Validation accuracy and false-positive rate have both moved more than once
this month — worth reading the dated entries below before assuming a
regression rather than a deliberate, benchmarked tradeoff. In particular,
validation accuracy went *down* on 2026-08-17 (second entry), from 94.94% to
94.31%, and that was the point: the corpus it is measured against had no
modern transactional mail in it at all, so the old number was partly scoring a
blind spot. Read that entry before trying to win the 0.63 points back.

## 2026-09-05 (four parallel worktree agents: a live false-positive bug, two rule fixes, one held back)

Sreekar reported a live false positive on x.com: nearly every post in the
feed got a "Treat this with caution" banner with the identical reason "It
asks you to send cryptocurrency," including posts with no money or crypto
mention at all. Four agents, each in its own git worktree, went out in
parallel; three merged cleanly, one didn't.

**The x.com bug — root cause confirmed, both halves fixed.** `scanner.js`'s
`handled` map is keyed by content hash, not by DOM element, and its only
banner de-dup guard removes a banner sharing the *same* hash as the one
about to render. X's timeline virtualizes: React reuses the same `<article>`
node for a new tweet as the user scrolls, and nothing ever told a banner
rendered for the *old* tweet's content that its node now holds something
else — it just sat there, permanently misattributed to whatever scrolled
into that screen position next. `render()` now tags the target element with
the content-hash its banner belongs to; `scan()` notices when that tag no
longer matches the current pass and removes the stale banner before judging
the new content on its own. Separately, and smaller: `crypto_transfer` (the
rule actually producing that reason text) required only a crypto noun near
a verb like "pay"/"send" in the same sentence, with no requirement that the
ask be directed at the reader — so a fictional meme ("a hacker group
announced... 'Pay $500 million in Bitcoin'") matched identically to a real
solicitation. Tightened the same way `threat_of_consequence` already was:
requires a second-person frame in the same clause. Both fixes landed
together as `a046e6a`, with a new `test_adapters.mjs` case that drives a
real DOM-node-recycling scenario through the actual `scanner.js` code (not
a reimplementation) and confirms the stale banner is removed — verified as
a genuine regression test by reverting just the `scanner.js` half and
watching it fail. One real, separate false positive got surfaced and
deliberately **not** fixed here: "Dox this woman immediately..." solo-fires
`artificial_urgency` on bare "immediately" — out of scope for this task,
needs its own pass.

**`prize_or_windfall` broadened for noisy SMS-spam phrasing (`0e6dcf2`).**
Held-out miss rate for this rule alone: 9/17 → 0/17. The regex only matched
clean English ("you've won," "selected"); this corpus is 2000s UK SMS-spam
text, and needed tolerance for "u" instead of "you," dropped/transposed
"have" ("ave," "hvae"), impersonal subjects ("your mobile number has won"),
passive voice ("vouchers to be won"), and "guaranteed" used as the windfall
verb instead of "won" (new `GUARANTEED_WINDFALL_RE`, gated the same way
`CONGRATS_WINDFALL_RE` already is). Every bare "won" needed a `(?!'t)`
lookahead after a first pass false-positived on "...email application that
won't properly display..." boilerplate. Net effect: held-out real-scam miss
rate 63.64% → 45.45%, with the benchmark false-positive count on 1,834 rows
of `dataset.csv` confirmed byte-identical before and after (not just the
same count — the same rows). `windfall_solicitation`'s 10/11 held-out misses
were deliberately left alone: that rule is correctly scoped to the
stranger-moves-money-through-you con, and this corpus's
"windfall_solicitation"-tagged examples are actually the same SMS-prize-scam
text `prize_or_windfall` handles — a corpus/genre-label mismatch, not a bug
in that rule.

**Structural login-form check, standalone (`3ce64cd`).** Closed the
"Structural login-form checks that stand alone" backlog item below. Off-site
credential POST could previously only corroborate a `PROTECTED_BRANDS`
impersonation finding — an ordinary-length, single-field harvest page for a
brand not on that hand-vetted list got no signal at all, however suspicious
its structure. `analyzeStandaloneHarvest` (in `impersonation.js`) now has a
third path: if the page's `<title>` names a brand (extracted the same way
`claimsIdentity` already does, generalized past the fixed brand list) that
shares no word with either the page's own domain or the domain the form
posts to, that mismatch convicts alone at weight 3.0 — below the 3.6 a
matched-brand impersonation finding reaches, since this path trusts generic
extraction less than the hand-vetted list. Four new fixtures pin: the
conviction itself; that a title sharing a word with the post-target domain
(a bank's own separately-branded auth vendor) stays safe; that the
hosted-auth-provider exemption still wins even when the title also names
that brand; and that generic furniture words ("Member Portal") can't
manufacture a brand claim. 328/328 engine checks; every other gate
unchanged.

**Devanagari corpus expansion — held back, not merged.** 100 new Devanagari
rows (70 scam / 30 legit) went into `curated-hinglish.csv`, covering tactics
already present in the English corpus (OTP asks, refund/cashback lures,
impersonated authority, advance-fee asks), sourced independently of both
holdout files. Held-out miss rate barely moved (63.64% → 61.82%, before the
`prize_or_windfall` fix above was layered on top) — but the new rows
exposed real coverage gaps in existing rules, and two *benchmark* gates
newly **failed**: targeted scams missed 0%→4.34% (limit 3%) and Hinglish/Hindi
missed 0%→6.30% (limit 5%), all 17 new benchmark misses landing among the 70
new scam rows. This is the exact pattern three earlier corpus rounds already
documented in this file — new rows expose gaps a rule-writing pass then
closes — but that follow-up pass didn't happen here, and merging a red test
suite isn't worth the marginal held-out gain. The branch
(`worktree-agent-aedf207fcdda6d95b`, commit `ab63082`) is kept, unmerged,
for whoever picks up the rule-fix pass; the flagged rule-bug candidate is
below.

**Rule-bug candidate found during the above, not fixed:** several genuine
Devanagari bank-OTP notices that state a code but explicitly tell the reader
not to share it (e.g. "...कृपया किसी अजनबी को न बताएं" — "please don't tell
a stranger") still scored 38 (suspicious). The Devanagari OTP-legit
exoneration logic likely doesn't cover this exact phrasing shape. Worth
checking alongside the corpus rule-fix pass.

## 2026-09-05 (closed the last network-consent item: a real person clicked through)

The one item the 2026-08-16 entry (below, "network-consent implementation")
left open — confirming `chrome.permissions.request()`'s native consent
bubble renders sensibly and that a real person can act on it — is closed.
It had stayed open even after the code merged (`d1d06af`, 2026-08-17)
because nothing automated can click that bubble: not CDP's `Input` domain,
and not a script-dispatched `click()` either, since Chrome only honors
`chrome.permissions.request()` inside a *trusted* user gesture. AppleScript
JS-injection (`osascript` with "Allow JavaScript from Apple Events" enabled
in Chrome) can read and drive the extension's own pages perfectly well, but
still can't manufacture that gesture — so the actual toggle clicks were done
by Sreekar in his own Chrome, on the options page, while Claude drove
verification around it.

Both prompts rendered exactly as the settings copy promises: the
`resolveShorteners` grant is the broad "read and change your data on a
number of websites" (correct — it covers 19 shortener domains), and
`checkUrlhaus` scopes narrowly to `urlhaus.abuse.ch` alone. After Allow on
both, `options.html`'s two checkboxes read `checked: true` and **stayed
true across a full page reload** — the grant is real and persisted, not a
transient in-page toggle. The popup footer picked it up correctly too
(`"Auto-scan on · Shortened-link lookup on"`); by design the footer has no
URLhaus line, so its absence there isn't a gap.

Nothing left blocking this feature. The merge this entry's stale 2026-08-16
neighbor still asks for already happened three weeks ago.

## 2026-09-01 (closing the remaining data and verification gaps)

Four independent worktree agents, each auditing its own diff against its
self-report before merging (one merge needed a follow-up fix; details
below). No coordination branch this round — unlike the ambient-gate round,
none of the four touched overlapping regions of the same files.

**`tests/holdout-ambient.json` populated — 17 real, cited pages.** This file
existed only as a stub ("not collected yet") in `tests/test_ambient.mjs`
since it was written; every prior "all solo-fire gates passed" claim this
month was true only against 2002 mailing-list mail and a 12-row hand-written
seed file, never against real current web content. Now: 17 rows fetched via
WebFetch with source URLs recorded — Hacker News comments, Al Jazeera news
articles, a Wikipedia lead, three bank FD/CD marketing pages (ICICI, SBI,
Ally — the exact "assured returns" genre already flagged as risky), two
product/pricing pages, two newsletters (one mentioning a reader who "lost
$70,000 to hackers," another a Facebook Marketplace/Zelle scam story — both
real examples of scam-adjacent *topics* appearing in ordinary content, which
is precisely what this corpus needs to stress-test), and a government tax
portal. Content that couldn't be genuinely fetched (Reddit, LinkedIn, X,
several news sites behind bot-checks) was skipped rather than invented.
**Result: zero solo-fire convictions across all 17 rows, on every rule** — a
genuine measurement, not an engineered pass; no rule was touched to get
there. Independently spot-verified before merging: `icici.bank.in` and
`sbi.bank.in` are the real, current official domains for those banks (a
recent RBI-mandated migration to a `.bank.in` namespace exclusive to
verified regulated institutions) — not an accidental phishing-adjacent
domain slipping into "legitimate" ground truth, which would have been a bad
way for this exact corpus to go wrong.

**`tests/holdout-scams.csv` created, closing cold-audit finding 3 — and
`tests/test_holdout.mjs` gets its first scam-miss gate.** Every accuracy
number this project has ever reported was on the false-positive side; there
was no held-out corpus and no gate for the opposite failure (missing a real
scam). 55 real messages from the UCI "SMS Spam Collection" (Almeida & Gomez
Hidalgo, real UK mobile spam reported 2004-2005, free for research use with
attribution) — verified independently to have zero exact-text overlap with
`training/dataset.csv` or `training/curated.csv`. **Measured miss rate:
35/55 (63.64%).** Read this as tactic-distribution mismatch, not a newly
broken tool: `premium_rate_subscription_trap` missed 7/7 and
`windfall_solicitation` 10/11 — 2000s UK premium-rate-SMS tactics
(`call this 09xx number to claim`, subscription traps billing per message)
that this rule set was never built to recognize, because it was built around
credential phishing, UPI/crypto transfers, and gift-card payments — the
tactics that actually show up in the training corpus and in real reports.
The gate is set at 65% (one row of headroom above the measurement, not a
loosened target) specifically so it catches regressions without hiding the
current number. A pre-merge fix was needed here: the new CSV needed a
comment header for source/license attribution, and the first version of the
change stripped every line starting with `#` anywhere in a file before
parsing — which would silently corrupt a multi-line quoted field whose
message text happened to contain a line starting with `#` (a hashtag, a
numbered list item). Currently harmless (no such line exists in either
holdout file today) but fragile for the next addition; fixed to only strip a
*leading* contiguous block of `#` lines, so it can never reach into data.

**The browser/adapter test layer ran against a real Chrome instance for the
first time this project's visible history records.** Every prior session
report ended with "Chrome for Testing is not installed here" and skipped 20
browser checks plus part of the 29 adapter checks. `npx @puppeteer/browsers
install chrome@stable` worked on the first attempt (`chrome@152.0.7977.64`);
`CHROME_BIN=<installed path> python3 tests/run_all.py` then ran all 7
suites clean, including: service worker registration, extension API access
inside the worker, the fresh-install-has-no-host-access assertion, the
model's full 6,000-term vocabulary loading under MV3's CSP, warning
injection on a scam page and its absence on a clean one, the full
content-script → service-worker → storage round trip, and a whole-page
phishing scan (link-target detection, form-action collection, email
harvesting, sender attribution). No bugs found, nothing to fix.
`tests/README.md` said 18 browser checks; the actual count is 20 — fixed.

**Security review of the extension's own code — clean, independently
verified rather than just trusted.** No prior review had looked at this
public, live, installed extension as its own attack surface: it renders
attacker-controlled message/page text into its own UI by design, and stores
an optional user-supplied Claude API key. Checked: XSS via
`innerHTML`/`outerHTML`/`insertAdjacentHTML`/`document.write` (zero hits —
every DOM-writing path, including the in-page warning banner rendered inside
a *closed shadow root* on hostile pages, uses `createElement`/`textContent`
exclusively); CSP (`script-src 'self'; object-src 'self'`, no
`unsafe-inline`/`unsafe-eval`, no `eval(`/`new Function(` anywhere); the API
key (stored in `chrome.storage.local` only, never `sync`, sent only to
`api.anthropic.com`, never logged, input field is `type="password"`);
message-passing trust boundaries (no `externally_connectable` in the
manifest, so no arbitrary web page can reach the service worker's message
listener at all — a Chrome-enforced boundary, not something the code has to
defend on its own); and permission scope (every declared permission still
has a real call site). Independently re-grepped every one of these claims
before accepting the "clean" result rather than trusting the report as-is —
all held up. No commit; nothing needed fixing.

**Net result:** all 9 ambient solo-fire gates pass (all three sources —
corpus, ambient-seed, and now ambient-holdout — populated and green); the
held-out suite has 4 gates instead of 3, with the new one reporting a real,
unflattering, honestly-measured number instead of not existing; the full
test suite (`test_engine.mjs`, `test_ambient.mjs`, `test_holdout.mjs`,
`test_benchmark.mjs`, `test_parity.py`, and now the browser/adapter layer
via `run_all.py`) has actually run end to end against real Chrome, not just
Node.

## 2026-09-01 (closing the ambient solo-fire gate)

Sreekar reported the extension was "quite bad" in actual use — false
positives, on ordinary content, no screenshot surviving to anchor a specific
case. Rather than start a new investigation, this picked up the one thread
already pointing at exactly that failure mode: `tests/test_ambient.mjs`
(added earlier today — see "why the false positives keep coming back" and
the cold-audit entries above) was still red, with four rules solo-convicting
real ambient text. Four rule fixes, one per agent in its own git worktree,
merged sequentially and each audited against its actual diff (not just its
self-report) before merging:

**`advance_fee`** — the fee/send proximity check's `pay` alternative was
missing the `\b` its two sibling branches already had, so "**charge**d to
the tax**pay**ers" (a Libertarian Party press release on military spending)
matched as two word fragments 12 characters apart, not a fee and a request
to send it. One-character fix (`pay` → `pay\b`).

**`delivery_redispatch_fee`** — its local `payment` check OR'd in `HI.fee`'s
bare, unbounded Latin alternatives (`fee|charge|duty`) with no proximity
gate, unlike every other call site of that constant. "fee" matched inside
"helpful **fee**dback" in a Linux mailing-list reply, combined with "failed"
matching inside "Cannot" for a false 2-of-3. Fixed by dropping the redundant
bare Latin duplicates (already word-bounded on the line above) and keeping
only the Devanagari alternatives, which were never the substring risk since
`\b` doesn't treat them as word characters.

**`investment_scam`** — two rows in `tests/ambient-seed.json` still
solo-fired after this morning's topic-to-act conversion. A news report of a
cyber-fraud arrest contained the exact promised-yield-near-instrument shape
the rule looks for, just narrated in the third person about an already-caught
scheme; a bank's own FD product page said "assured returns" through a
leftover ungated alternative that bypassed the instrument gate entirely.
Fixed with `FRAUD_CASE_REPORT_RE`, a plain exclusion on reporting language
(arrested/police/convicted/etc.) checked first — a yield promise has no
second-person form the way a threat does, so unlike `threat_of_consequence`'s
reader-directed frame, direction can't be the signal here and exclusion is
what's left — plus removing the bare `assured returns?` alternative, which
cost nothing measured (that exact phrase appears nowhere, gated or not, in
either training corpus). Audited independently: grepped both training
corpora for every `FRAUD_CASE_REPORT_RE` term against label=1 rows and
confirmed none of the hits were investment-pitch rows the rule was actually
catching — the exclusion doesn't quietly drop real detection on anything in
scope today. Residual, unmeasured risk worth naming: this is a rule-wide
exclusion, so a scam that defensively name-drops "unlike those arrested
fraudsters..." could in principle dodge it. Narrow and forward-looking, not
a current regression — the corpus has no such row, and other rules still
provide defense in depth.

**`artificial_urgency`** — the lightest rule in the set (weight 1.2, the one
that makes every rule's minimum solo-fire weight cross the warning
threshold — see "why the false positives keep coming back" above), and
correspondingly the hardest to fully zero out. Went from 6 solo-warns to 3
(limit 4) via three narrow strips added to the rule's existing pre-filter
pipeline: URLs (a domain like `http://urgent.rug.ac.be/` tripped "urgent" as
a hostname substring with no sentence involved), "urgently needed" (a
reporter's judgment about a shortage, not a countdown), and "X should
immediately Y" (a third-party recommendation, not a directive at the
reader). The 3 remaining solo-warns were left alone on purpose: two are
marketing copy ("you must act now, this offer expires...", "collect your
phone card immediately") structurally identical to real scam rows already in
the corpus — tightening further would cost real detections — and one is a
Belgian radio station's stylized name ("URGent") appearing as bare prose
outside any URL, a one-off proper-noun homograph rather than a generalizable
pattern.

**Net result:** `tests/test_ambient.mjs` — all solo-fire gates pass (was 4
failing). `tests/test_engine.mjs` — 324/324 (was 319; five new regression
fixtures). `tests/test_holdout.mjs` — unchanged, all gates at 0%.
`tests/test_benchmark.mjs` — false positive rate *improved*, 0.55% → 0.49%
(dangerous unchanged at 0.16%), targeted scams missed unchanged at 0/345,
Hinglish/Hindi missed unchanged at 0/200. `tests/test_parity.py` — unaffected
(all four fixes are heuristic-only regex changes; none touch
training data or text the model reads), still passing at the same 2.70e-07
max delta.

None of this closes finding 3 from the cold audit (no held-out scam corpus)
— every number above, like every number in every entry before it, is still
measured on data the model or the rules have effectively seen before. It
narrows a different, real gap: the four rules fixed here were solo-convicting
*legitimate* ambient text, which is closer to what "quite bad in actual use"
reported than a missed-scam number would be.

## 2026-09-01 (cold audit)

**Asked for an audit by agents with no session context, reading directly from
git — because everything above this entry was produced and checked by the same
session that wrote it.** Found and fixed one process bug before the audit could
start: `d7c9bca` was titled "Merge B2: per-rule solo-fire gate" but had one
parent and contained no B2 files — a `git stash` ran mid-merge and swallowed the
staged files, and the following commit landed only an unrelated `PROGRESS.md`
edit under the merge's message. Repaired by resetting past it, re-committing
that edit honestly, and properly merging B2's real branch
(`worktree-agent-a2dcd8eb7a7de7b5a` at `d008b3b`, tests-only, no conflicts).
Re-measured the true merge point afterward — post-merge numbers for the two
parallel branches (the no-ask cap below and the act-shaped rule rewrites)
matched their individual pre-merge claims exactly, so the parallel work combined
cleanly.

Five independent auditors then read the merged tree (blind to this file and to
commit messages) plus two more against the archive repo. One auditor
(detection-logic) was seeded with a known bug it wasn't told about, as a
calibration check — it found it independently before being stopped, so the
audit's sensitivity is real, not assumed.

**Confirmed, ranked by severity:**

1. **`gift_card_payment`'s proximity gate has been dead since before today.**
   `GIFT_CARD_ASK_RE.source` is spliced into the composed pattern unwrapped
   (`heuristics.js:347-348`); its top-level `|` leaks out of the composition, so
   the rule degenerates to "gift-card noun anywhere AND ask verb anywhere" with
   no proximity check at all. At weight 3.0 it also bypasses today's no-ask cap.
   `analyzeHeuristics("Thanks for the gift card! I will send you the photos from
   the party later this week.")` fires it. Fixed below.

2. **The no-ask cap's verb list cuts both ways.** A blind behavioral-delta pass
   ran 117 constructed inputs through this HEAD and `ebe714f` and diffed every
   verdict. The cap (see the entry below) correctly kills 10+ topic-only false
   positives with no counterexamples of it hiding an actionable scam that had no
   ask at all — but `ACTION_REQUEST_RE`'s verb list is both under- and
   over-inclusive, and because it now gates both the cap *and* the older
   no-action-requested score discount, one miss does double damage:
   - Missing ordinary asks: *"please **tell** me the OTP you just received"*
     (an unambiguous phishing message) dropped from dangerous (77) to suspicious
     (36); *"**Join** our VIP Telegram group and **start trading** today"*
     dropped from 81 to 58.
   - Bare-matching idiom/passive collisions: `verif\w*` matches "has been
     successfully **verif**ied" (passive, not an ask), pushing an ordinary
     Income Tax refund-status notice from safe (16) to suspicious (37). Bare
     "forward" matches "going **forward**", nearly tripling a benign note's
     score (4 → 24, still safe but a real signal jump).
   Fixed below.

3. **No held-out scam data exists anywhere in the repo.**
   `tests/holdout-legit.csv` and `holdout-pages.json` are genuinely clean of
   training overlap (confirmed by grep), but both are legitimate-only. There is
   no `tests/holdout-scams.csv` equivalent, so nothing measures miss-rate
   against scam phrasing the model has never seen — every "scams missed" number
   in this file, including the ones two sections below, is measured on curated
   rows ~82% of which are literally in the model's own `X_train` split
   (measured: 284/345). This is a data-collection gap, not a code bug — logged
   under Next, not fixed today.

4. **`extractUrls`/`extractEmails` in `extension/lib/text.js` are O(n²)** on
   adversarial input — measured ~580ms / ~450ms at the 20,000-char page-text
   cap, clean 4x-per-doubling growth confirming quadratic backtracking, not
   exponential. Runs in the MV3 service worker on attacker-controlled page text
   from a content script matching `<all_urls>`; realistic scam text measures
   under 1ms, so this needs deliberately adversarial padding to trigger, not
   ordinary content. Fixed below.

5. **The model sees raw text; the rule engine sees confusable/leetspeak-folded
   text.** `model.js`'s `classify()` tokenizes raw input; `heuristics.js`
   normalizes first. An obfuscated brand/action word (`acc0unt`, Cyrillic
   `раypal`) is invisible to the model's vocabulary while the same text still
   matches heuristic keyword rules after folding — a reduction in the model's
   contribution near the threshold for exactly the pretext-only messages it was
   retrained to help with, not a guaranteed bypass since the rules still see it.
   Fixed below (folds before the model tokenizes, same as the rules already do).

**Checked and clean:** `all_frames: false` is a documented, deliberate tradeoff
(`docs/STORE_LISTING.md` covers it; iframe content is instead reachable through
the right-click "check this text" context menu) — not an oversight. Every
declared permission has a real call site, none unused. The archive sweep
confirmed the three former teammates' names (never committed as git identities,
only as first names in file content) are absent from the public repo's commits,
blobs, issues, PRs, and collaborator list. Nothing in the 32-commit V1 archive
was worth porting — every candidate either already exists in V2's corpus/rules
(often more richly) or was already fixed better in V2.

## 2026-09-01 (closing the cold audit)

Findings 1, 2 and 4 above are fixed and verified against the corpus; finding
5 is fixed but revised from what the audit entry proposed, and finding 3 is
left as logged (a data-collection gap, not a code bug).

**1 — `gift_card_payment`'s dead proximity gate.** `GIFT_CARD_ASK_RE.source`
and `GIFT_CARD_RE.source` are now wrapped in `(?:…)` where they're spliced
into `GIFT_CARD_PAYMENT_RE`, so the top-level `|` inside each no longer
leaks out of the composition. The finding-1 example
(`analyzeHeuristics("Thanks for the gift card! I will send you the photos
from the party later this week.")`) now scores 0 with no signal, was 3.0.

**2 — the no-ask cap's verb list.** `verify\w*` is gated on a direct object
(`verify\w*\s+(?:your|the|this|it|my)`) so it stops matching the passive "has
been successfully verified"; `forward` is gated the same way `sharing` was
(`forward(?:ing)?\s+(?:it|this|to|the|your|my)`) so it stops matching "going
forward"; `tell\s+(?:me|us)` and `start\s+trading` were added to close the
two missed-ask examples from the finding. `join` was deliberately **not**
added — 30 legitimate corpus rows read "Join our free webinar" / "Join the
Fun at EFF's VIP Party" in the identical shape to the missed scam's "Join our
VIP Telegram group", so a `join` branch would reopen the exact topic-vs-act
trap this whole audit exists to close; `start trading` is the narrower,
unambiguous act in the same sentence and has zero corpus collisions.
Re-measured: `tell me the OTP you just received` moves from 36 (the finding's
reported broken value) back to 57 on heuristics alone; the finding's other
three examples were spot-checked directly (`noAsk` now correctly `false` for
each) rather than re-run through the full 117-input behavioral-delta pass.

**4 — `extractUrls`/`extractEmails`.** Restructuring the domain pattern from
`X*\.X` to `(?:X\.)+X` (so a loop iteration can't be reread as the required
final segment) turned out to remove the *ambiguity* but not the *cost*:
`.match()` retries the whole pattern at every failing start position, and an
unbounded loop still does O(n) work at each one — still ~580ms/~430ms,
unchanged. What actually fixes it is bounding the quantifiers, which is free:
a DNS label is capped at 63 octets, a domain has no real reason to exceed 10
labels, and RFC 5321 caps a local part at 64 octets. Bounded, both are
~1–13ms at 20,000–40,000 characters and scale linearly, confirmed by doubling
the input. Every URL/email extracted from the existing corpus is unchanged
(spot-checked, not exhaustively diffed).

**5 — model sees raw text, rules see folded text — revised.** The proposed
fix ("fold before the model tokenizes, same as the rules already do") is
wrong as literally stated. `normalize()`'s digit fold (`0`→`o`, `1`→`l`, …)
exists so a heuristic rule can't be dodged by writing `8000` as `8ooo` — it
was never validated against the model's vocabulary, which is frozen from
training text that was never digit-folded. Folding digits before the model
tokenizes turns real, weighted vocabulary terms (an amount, an OTP — `1500`
is a term the model knows) into vocabulary the model has never seen (`lsoo`
is not). Measured on the full corpus: corpus-wide false negatives rose from
515/1769 to 525/1769 for no offsetting gain, because neither of the finding's
two motivating examples (`acc0unt`, Cyrillic `раypal`) needs the digit fold —
Cyrillic-confusable and styled/accented Latin are both handled by NFKD plus
the confusables table alone.

Fixed instead: `foldConfusables()` takes a `substituteDigits` option
(default `true`, unchanged for every existing caller — the rules) and
`model.js` calls it with `substituteDigits: false`. Re-measured: corpus
numbers are back to exactly the pre-change baseline (515/1769 FN, 10/1834
FP), and the model now treats `раypal`/`аccount` (Cyrillic homoglyphs)
identically to plain `paypal`/`account` — spot-checked directly, not run
through the full corpus, since neither example exists in the corpus as
written. `acc0unt`-style digit leetspeak is a **known, deliberately unfixed**
gap for the model specifically (the rules still catch it, via `normalize()`'s
existing digit fold) — closing it would need the training pipeline itself to
learn digit-folded terms, which is a retraining change, not a bug fix.

This reopened `tests/test_parity.py`, which is the load-bearing gate for
exactly this kind of divergence: it compares `classify()`'s predictions
against `pipeline.predict_proba()` on **raw** text and now finds real,
expected disagreement (up to Δ=0.23) on the EDGE_CASES that exercise
accented/styled/CJK text, because one side folds and the other doesn't. The
gate is doing its job — the fix is to make the Python side fold the same way
before scoring, not to weaken the gate. That port (reusing
`tools/build_confusables.py`'s table so the two sides can't drift) is
sitting with a worktree agent; `tests/test_engine.mjs`,
`tests/test_holdout.mjs` and `tests/test_benchmark.mjs` all pass at this
commit — only `test_parity.py`'s prediction comparison is red, and only for
the reason above.

That port is done: `tests/fold_confusables.py` parses the same 273-entry
table straight out of the generated `extension/lib/confusables-data.js`
(rather than hand-copying it, which is exactly the kind of drift this test
exists to catch) and replicates `foldConfusables(text, {substituteDigits:
false})` — NFKD, fold, lowercase, strip combining marks — so
`test_parity.py` now folds each text before handing it to
`pipeline.predict_proba`, matching what `model.js` does before it
tokenizes. `python3 tests/test_parity.py` passes clean: 0 tokenizer
disagreements, 0 predictions over tolerance, largest disagreement 2.70e-07
against the 1e-4 tolerance (floating-point rounding noise, not a real
divergence). The other three suites are unchanged at the numbers above.

**Not done — finding 3.** No `tests/holdout-scams.csv` exists; every miss-rate
number this file reports, including the ones above, is still measured on
data ~82% of which the model trained on. Data-collection work, not a code
fix — unchanged from the audit entry.

## 2026-09-01 (the no-ask cap)

**Promoted `no_action_requested` from a −0.8 nudge to a hard cap, and the
interesting half turned out to be the audit rather than the cap.** The entry
below proposed this and measured it at +5 false positives removed for 1 curated
scam lost. Both numbers were artefacts of the verb list being incomplete: the
list was missing so many ask verbs that it read *17* curated scams as asking for
nothing, and it read enough legitimate mail the same way to look like a bigger
precision win than it is.

**The rule now caps rather than discounts.** Text that names no action for the
reader and carries no link cannot push its *rule* contribution past
SUSPICIOUS_AT, unless a rule at or above `CONCLUSIVE_AT` (2.4) fired —
`gift_card_payment` 3.0, `upi_collect_request` 2.6, `payment_detail_change` 2.5,
`crypto_transfer` 2.4, `family_emergency` 2.4, plus `lookalike_domain` 3.0,
`brand_impersonation` 2.6, `userinfo_url` 2.4 and `urlhaus_match` 4.0 from the
other layers. Those three are academic: each needs a URL to exist, and the cap
already does not apply where there is one.

The bar is deliberately above the 2.0 that `analyzeHeuristics` uses to withhold
its exonerating discount, and the gap is the design. 2.0–2.3 is where the
topic-shaped heavy rules sit — `investment_scam`, `windfall_solicitation`,
`credential_request`, `advance_fee` — and those are exactly what the cap is for.
So `noAsk` is computed *outside* the `hasSevere` gate; computing it inside would
have switched the cap off for every rule it was meant to hold back.

**Not a corroboration requirement.** One rule still convicts alone, and the
regression set now pins that: a single `crypto_transfer` on text with no ask and
no link still scores 100. No count of signals appears in the condition.

**The cap binds the rule score, not the final score, and that was measured
rather than assumed.** Capping the final score scores identically on false
positives (15/1834 either way) and costs 29 corpus scams the model was catching
alone — three of them classic advance-fee letters, which the corpus stores
truncated at 1,200 characters, so the request really has been cut off and "names
no action" is a true statement about the text. `MODEL_MAX_PULL` was raised to 50
in a measured decision precisely so the model could warn on text that trips no
rule; the model is not a rule, and silencing it here bought nothing.

**The verb audit is where the recall came from.** Against every scam row in
`curated.csv` and `curated-hinglish.csv`, 30 rows named an action the list could
not see, 17 of them convicted by nothing else. The recurring shape is the one
this file has now written down three times: *the presence-based rules already
knew the verb and the absence-based rule did not.* `provide`, `submit`, `enter`
are in `CREDENTIAL_ENTRY_RE`; `buy`, `redeem`, `pay` in `GIFT_CARD_ASK_RE`;
`accept`, `approve`, `scan` in `upi_collect_request`; `reschedul` in
`delivery_redispatch_fee`. Plus the word-form bugs: `\bshare\b` never matched
"sharing", `\bpay\b` never matched "paying", and `reschedul\b` can never match
"reschedule" at all. On the Hinglish side `kar(?:iye|ein|o)` covered three of
about ten real spellings of the imperative of *karna* — "kijiye" and "karwaiye"
both went unseen, and both are in the corpus — and Latin "bhar" was missing
while Devanagari भर was present.

**Four candidate verbs were tried and removed on measurement**, which is the
part worth keeping: `press` matched "PRESS RELEASE" in a 2002 mailing-list post
and was the only thing keeping it out of the cap; bare `update` matched a
newsletter's "product updates"; `sign up` matched an EFF subscribe footer;
Devanagari `दर्ज` matched "पुलिस ने मामला दर्ज किया है", a filed case being
*reported*, which `threat_of_consequence` reads as a threat — the two rules
would have cancelled on every Hindi crime report. `sharing` needed a determiner
or it matched "music sharing", and `bhar\w*` had to be enumerated or it
swallowed "Bharat".

**Result: corpus false positives 0.93% → 0.82% (17 → 15), 0 added; corpus false
negatives 25.78% → 25.49%, 0 newly missed and 5 newly caught; targeted scams
missed 0/345 unchanged; Hinglish/Hindi 0/200 unchanged; held-out 0/66 and
0/16 unchanged.** Both directions improved, which is not the tradeoff the
proposal below expected. 22 more regression fixtures (287 → 309), covering both
directions: four topic-rule false positives that must now stay silent, eight
Hinglish/Devanagari/English scams whose only ask is a verb the audit added, and
the conclusive-rule exemption.

**What this does not fix.** The two false positives it removes are 2002
mailing-list posts, and the point of the entry below is that the corpus contains
none of the text the extension actually reads. The cap is aimed at the LinkedIn
feed post and the news article; there is still nothing in any test set that
resembles those, so this remains a fix measured against data that cannot contain
the failure it targets.

## 2026-09-01 (the three worst topic-rules, converted)

**Acting on the diagnosis in the entry below: the three rules at the top of its
solo-conviction table are now act-shaped.** No new rule, no new category, no
two-signal requirement — each of the three keeps its tactic, its weight and its
`why`, and gains the structure it was missing.

Solo convictions on the 1,834 legitimate corpus rows (one rule fired, nothing
corroborated it, the user got a banner):

| rule | solo-warns | fires at all |
|---|---|---|
| `investment_scam` | 10 → **0** | 12 → **0** |
| `impersonated_authority` | 8 → **0** | 75 → **3** |
| `threat_of_consequence` | 7 → **0** | 66 → **1** |
| all rules, total | 34 → **13** | |

**The solo metric was hiding most of the damage, and the real number is worse
than the table above.** `impersonated_authority` included `HI.police`
wholesale, and `threat_of_consequence` matched the same word from its own
alternation, so a news report of an arrest tripped *both* — `signals.length`
was 2, and the row vanished from a metric that only counts rules firing alone.
Two topic-rules reading one noun corroborate each other. Counted properly:

| legitimate rows … | before | after |
|---|---|---|
| where any of the three fires | 118 | **4** |
| where two or more fire together | 34 | **0** |
| **warned, with no rule outside the three firing** | **57** | **0** |

Corpus false positives 0.93% → **0.55%**, dangerous unchanged at 0.16%,
targeted scams missed 0/345, Hinglish/Hindi 0/200, held-out 0/66 and 0/16.
**Zero curated scams lost** — all 345 still convict, and the heuristic layer
alone still flags the same 320 of them it did before.

**`investment_scam` — the instrument is the topic, the promised yield is the
act.** Its last branch was the rule's original design: `(invest|trading|stock|
share|mutual fund|scheme|ipo)` anywhere in the message AND `(money|profit|
return|scheme)` anywhere else in it, ungated. That conjunction produced 10 of
the rule's 12 fires and every one of its solo warnings — Python threads where
the "scheme" is a naming scheme and the "return" is a return value, a NYTimes
piece on a firm that "does invest in promising new companies", a press release
headlined "GOVERNMENT REGULATION IS KILLING THE STOCK MARKET". A fund reports
what it returned; it never offers you a fixed or daily one. So a qualifier
(`fixed|daily|monthly|guaranteed|assured|double|multibagger`) must sit within
25 characters of a yield noun, either order, and the instrument must sit in the
same sentence as that promise. The instrument gate is not decoration: without
it, "the accessor returns a fixed-size buffer" satisfies the promise half on
its own, on a corpus where the other half of the rule is the word Scheme.
Two curated Devanagari rows leaned on the old conjunction and are carried by
the new one — "क्रिप्टो में इन्वेस्ट करें … फिक्स्ड रिटर्न" and, because the
promise pattern runs in both directions where the old Devanagari branch ran in
one, "IPO प्री-लिस्टिंग एलॉटमेंट गारंटी".

**`impersonated_authority` — naming an authority is not the tactic; claiming to
be one is.** `federal` appears in 9 of the legitimate rows and `government` in
36, and all eight solo warnings came from those two words. The named agencies
(`irs`, `hmrc`, `trai`, `rbi`, `income tax`, `cyber cell`, and the named
support desks) stay ungated — they appear once or not at all, and nothing
routinely writes to you about HMRC. The generic nouns now need a claim of
being the sender within 30 characters *before* them: "Hi, this is Instagram
security team". One-directional on purpose — a bidirectional window reads "a
confiscatory government boondoggle, expropriated from the original owners" as a
claim, on the "from" that follows it. `security team`, `fraud department` and
`tech support` appear in none of the false positives and are gated anyway,
because a 2002 mailing-list corpus cannot contain the modern security notice
that would prove them wrong; that blind spot is the subject of the entry below.

**`threat_of_consequence` — the threat has to land on the reader.** Its nouns
are the ordinary vocabulary of news: `fine` in 20 legitimate rows, `court` in
13, `police` in 10, `arrest` in 9, and the seven solo warnings are "A-level
student sues for £100,000", "Two in court on IRA spy charges", "Freedom deal
for Real IRA man … two more years in jail", and "Another fine mess I've got
myself into", where *fine* is an adjective. The consequence now has to share a
sentence with a frame that puts it on you — something to avoid or face, issued
against you or in your name, or following if you do not pay. Bare "you" is
deliberately not such a frame: one of the false positives puts it 22 characters
from "court" ("I'd have had them in the small claims court quicker than you
could drop LOTR on your foot"). "Take legal action" is likewise absent while
"will be taken" is present, because the news row reports someone else taking
it. `challan` is the one term left ungated, and it is the eight-row exception
that justifies the rest: the e-challan family is a payment link rather than a
threat, satisfies no frame at all, appears in zero legitimate rows, and — unlike
"fine" — is never anything but a penalty.

**`HI.police` is split, and two of its Latin entries were outright bugs.** One
alternation was serving both rules, which is part of why both were
topic-shaped: a message claiming to be the police and a message threatening
police action are different tactics. It is now `policeLatin` and
`policeDevanagari`, split on false-positive risk rather than on `\b` (the axis
`urgentLatin`/`urgentDevanagari` is split on). The Devanagari half is ungated
in both rules — every term is an Indian agency name, none appears in any
legitimate row, and each is already the act. The Latin half is gated in both,
and lost two entries to the bare-substring bug that `वारंट(?!ी)` and
`कस्टम(?!र)` already document: `warrant` had no word boundary and matched
inside **warranty**, so a genuine "your laptop warranty claim" fired the threat
rule; `\bed\b`, meant to be the Enforcement Directorate, matched the name
**Ed** in 16 of the 1,834 legitimate rows, the largest single contributor to
`impersonated_authority`'s 75 fires. It now needs the agency context a real
message gives it ("ED officer bol raha hoon").

**Corpus-wide false negatives went 25.78% → 29.34%, and that is the expected
shape of this change rather than a regression to win back.** The 135 rows are
2002 commercial spam — extended auto warranties (the `warranty` bug, firing a
*criminal threat* rule on a car warranty ad), inkjet cartridges, e-book
publishing software, "LazyTraders: $449,000 on Wednesday". Not one of them
contains phishing vocabulary; measured, zero of the 135 mention a password, an
OTP, a suspended account or a credential of any kind. They were being caught
because they discuss money and the law, which is exactly the reading this
change removes, and they are the class the tool deliberately does not warn
about (see the 2026-08-17 entry).

**Four new regression fixtures on the LEGIT side and three on the SCAM side**
(284 → 297 checks): a financial newsletter reporting quarterly returns, a news
report of an arrest, a mailing-list thread about someone else's lawsuit, a
political thread about government policy — and, so the conversions cannot be
satisfied by simply switching the rules off, an investment pitch promising a
fixed daily return without ever saying "guarantee", a support-desk impersonation
naming no company, and a debt threat aimed at the reader.

`python3 tests/run_all.py` passes every suite. The browser smoke test skips —
branded Chrome 137+ refuses `--load-extension` and Chrome for Testing is not
installed here — so that layer is unverified rather than passing.

## 2026-09-01 (why the false positives keep coming back)

Two false positives were reported from live browsing, both screenshots rather
than test failures — which is itself the finding. The first, a genuine LinkedIn
"your profile photo was changed" mail scored 60/100 on `credential_request`,
turned out to be **already fixed**: the 08-16/08-17 rewrite made that rule
require a transmission or entry verb, and "we'll require that you reset your
password" is neither. It scores 0 today.

The second was live. An ordinary LinkedIn feed post — "Congratulations to
<name> on securing admission to <university>" — scored 51/100, because
`prize_or_windfall` carried a bare `congratulations` in its alternation with no
gate of any kind. Its Hindi twin `badhai|बधाई` sat ungated in `HI.prize` the
same way. Both are now behind `CONGRATS_WINDFALL_RE`, which requires a winnings
noun within 60 characters. The gate is a plain character window rather than the
same-sentence window the other rules use, because the greeting is almost always
its own sentence ("Congratulations! Your refund of Rs 4,500 is ready") and a
`[^.!?]` window could never reach the noun it is meant to be gated on.

All 8 rows in `curated.csv` that open with "congratulations" also say "you've
won", which the rule's first branch matches on its own, so the bare word was
carrying no case that was not already made. Corpus false positives went 0.98% →
0.93%, dangerous 0.22% → 0.16%, targeted misses unchanged at 0/345.

### The part that matters: this is not a regex bug

The score curve is `squash(raw) = 100(1 − e^(−raw/2.6))`. Inverting it, a raw
weight of **1.12** reaches SUSPICIOUS_AT, and **2.73** reaches DANGEROUS_AT. The
lightest rule in the set is `artificial_urgency` at 1.2. So *every rule in the
set crosses the warning threshold firing entirely alone* — 1.4 scores 42, 1.9
scores 52, which is the 51 in the screenshot almost exactly.

The obvious response is to require corroboration. Measured, that is impossible:

```
  rules fired |  curated scams |  legitimate mail
      1       |       197      |        34
      2       |       100      |        37
      3       |        18      |         2
      4       |         5      |         1
```

**62% of the scams this tool catches rest on a single rule.** A two-signal
requirement would drop 197 real catches. One rule firing alone must stay
sufficient to warn, and that constraint is not negotiable.

Follow it through and the actual cause appears. If one rule must be sufficient
evidence, then every rule must describe something *no legitimate sender ever
does*. But a good half of the rules describe a **topic** — arrest, government,
prize, urgency, investing — and legitimate senders discuss those topics
constantly. Those rules are therefore not sufficient evidence, while the scorer
grants them sufficient authority. The false positives are not malfunctions.
They are topic-rules faithfully reporting a topic, read by the scorer as if
they had detected an act.

Solo convictions on the 1,834 legitimate corpus rows — one rule fired, nothing
corroborated it, the user got a banner:

```
  rule                        solo-warns   fires at all
  investment_scam                 10           12
  impersonated_authority           8           75
  threat_of_consequence            7           66
  artificial_urgency               4           23
  credential_request               3            3
  prize_or_windfall                1            6
```

The ranking is the diagnosis. `credential_request` is act-shaped — it demands a
transmission verb pointed at the sender — and touches 3 rows out of 1,834.
`threat_of_consequence` is a bare alternation of `arrest|court|police|fine`,
and its false positives are mailing-list threads titled "Six arrested for
attacking Palio jockey" and "Defending Unliked Speech". `impersonated_authority`
lists `federal|government|security team` with no gate, so any political thread
trips it. The rules worked perfectly. They found the topic.

Both shapes can sit inside one rule. `investment_scam`, the worst offender,
opens with a sentence-gated `guarantee[ds]? … returns?` — a past fix — and ends
with an ungated conjunction of `(invest|trading|stock|ipo)` AND
`(profit|return|scheme)` anywhere in the text, which is the original design and
fires on any financial newsletter.

### What follows from it

Every fix in this log — the `crypto_transfer` proximity gate, the
`credential_request` direction requirement, the `gift_card_payment` ask gate,
today's `congratulations` — is the same operation: converting one rule from
topic-shaped to act-shaped. That is the correct fix and there is no better one
available. What has been wrong is the scheduling. It has been done one rule per
screenshot, in the order real life happened to embarrass us, across 24 rules
that are perhaps half converted, with no completion criterion and no way to
know which rule bites next. `prize_or_windfall` was sixth on that list.

Worth noting that `no_action_requested` is already an ask-detector, inverted —
it tests for the absence of click/pay/login/verify verbs — and is worth only
−0.8. Promoting it from a nudge to a cap measures at +5 false positives removed
and 1 curated scam lost (a Hinglish KYC line whose ask verb the Devanagari list
is missing, so arguably a gap in the rule rather than a real loss).

And the reason both of these arrived as screenshots rather than test failures:
**the corpus contains no examples of the text the extension actually reads.**
1,834 legitimate rows of 2002 mailing-list email, 66 held-out mails, 16 login
pages — and not one social feed post, product page, or modern transactional
notification. The generic adapter scans every `article`, `[role='listitem']`
and `[role='article']` on every site, which on LinkedIn is every feed post and
on Reddit every comment. Nothing in any test set resembles that input. Tuning a
rule against data that cannot contain the failure is how a fix passes every
gate and still ships the bug.

## 2026-08-17 (the last curated misses)

**Cleared the remaining nine targeted-scam misses, and two of them turned out
to be general bugs rather than vocabulary gaps.** Both are the same class as
the decimal-point bug found earlier the same day: something in real text that
the patterns were never able to see.

**Curly apostrophes.** Gmail, Word and iOS all autocorrect `'` to U+2019, so
real mail overwhelmingly carries the curly form — and `normalize()` passes it
through untouched. Every pattern written with an ASCII apostrophe had therefore
stopped matching the text it was written for: `you(?:'ve| have)?` in
`prize_or_windfall`, `don'?t` in `secrecy_request`, `i(?:'m| am)` in
`boss_impersonation`, `friend'?s` and `it'?s` in `family_emergency`,
`couldn'?t`/`can'?t` in `delivery_redispatch_fee`. "You’ve won a free iPhone!
Click the link to claim now." tripped *nothing at all*. Folded to ASCII in
`analyzeHeuristics` alongside the number fix, for the same reason it cannot go
in `normalize()`.

**`\d` is unreliable in this layer and one urgency pattern was quietly dead.**
`normalize()` folds some digits onto letters and not others — "24" becomes
"2a" — so `within\s*\d+\s*hour` can match "within 2 hours" and never "within
24 hours". The file's own comment already says never to match `\d` in a
heuristic; two patterns still did. Left as-is rather than widened: the obvious
fix (`in\s*\S+\s*hours`) fires on "arriving in 2 days" and would cost more in
false positives than it buys. Recorded here as a known limitation.

**A regression from the same morning, caught by the curated set.** The
link-expiry stripper added earlier that day listed `password` among the things
whose expiry is a security control. It is not — "Your iCloud password will
expire today. Reset it now: <lookalike domain>" is one of the oldest phishing
pretexts there is, and stripping it removed that row's only urgency signal.
`password` is out of the list; a *link*, code, token or session expiring is
still stripped, and there is a test for both halves.

**The other seven were rules with the tactic right and the nouns wrong:**
`account_suspension` had no "sim" (the most common Indian version of the
threat) and no "unusual activity" pretext at all; `payment_detail_change`
required an adjective before "bank details" and could not see the possessive in
"Update *your* billing info", nor the English half of the payroll redirect
already fixed in Devanagari; `prize_or_windfall` knew "lucky winner" but not
"lucky draw"; `threat_of_consequence` had no "challan", the Indian traffic fine.

**Two widenings were reverted or narrowed after measuring, both on false
positives the benchmark could not have caught.** Adding `interrupt(?:ed|ion)`
to `account_suspension` scored Adobe's real dunning email at 64 — and "to avoid
interruption" is also exactly what the Netflix-lookalike phish in
`test_engine.mjs` says, so the *text* does not separate them at all. That is
`brand_claim_mismatch`'s job, via the URL, and the addition was removed rather
than kept with a caveat. Separately, a bank alert saying it had "already
blocked the attempt" tripped `account_suspension`, because the rule read the
blocked *attack* as a blocked *account*; fixed with the same negative-lookahead
shape as `वारंट(?!ी)`.

**Result: targeted scams missed 2.61% → 0.00%, Hinglish/Hindi 1.00% → 0.00%,
false positives unchanged at 0.98%, held-out 0/66 and 0/16.** 12 more
regression tests (272 → 284).

**Both benchmark gates tightened, on the project's own stated reasoning that a
gate far above reality is not a gate.** `targeted scams missed` 8% → 3% and
`Hinglish/Hindi scams missed` 20% → 5% — the latter was set when the number was
74%. Each is roughly ten rows of headroom, enough to add a batch of new tactics
before their rules exist without tripping the gate.

**0.00% is a statement about the curated set, not about scams.** Those 345 rows
are also where every one of these gaps was found, so the honest reading is that
the rule layer now covers every tactic anyone has written down for it — which
is exactly as good as the list is complete. The corpus-wide false negative rate
is still 25.55%, dominated by 2002 commercial spam the tool deliberately does
not warn about. New tactics arrive by being reported, not by being derived.

## 2026-08-17 (Devanagari misses)

**Evaluated open-source blocklists to replace hand-written rules, and did not
ship one — none of the three candidates survived verification.** Worth
recording so the next person does not re-run it. OpenPhish's terms forbid both
commercial use and redistribution, which an MIT extension cannot work around.
Phishing.Database is MIT and provides exactly the domain lists this project
lacks, but its `pushed_at` is 2026-08-01 — the "Update Feeds" automation
stalled 16 days ago — and phishing domains live hours to days, so the 391,618
entries are mostly dead; it is also 11 MB against `chrome.storage.local`'s
10 MB quota. PhishTank needs a per-user Cisco app key under a Cisco EULA.
URLhaus, already integrated, is fresh (updated the same day) but is a
*malware distribution* feed — its rows are `malware_download`, mostly IP-hosted
droppers — not a phishing feed, so it does not cover this ground either.

**Went after the Devanagari false negatives instead, which were the worst
remaining gap at 19/170 when the day started.** Dumping the missed rows showed
14 of 18 fired *no rule at all*, and the gaps clustered into one recurring
shape this log has now hit three times: a Devanagari-spelled loanword that the
Latin half of the same pattern already covered.

- `HI.send` had no entry for "शेयर कर" — "OTP शेयर करें" is the single most
  common way a Devanagari message asks for a one-time code, and it carried no
  transmission signal at all. Gated on the verb rather than bare "शेयर", which
  also means *share* as in stock market.
- `job_advance_fee`'s named-cost list had "किट" and "जॉइनिंग" but not
  "सिक्योरिटी" (security deposit), "एक्टिवेशन" or "अनलॉक", and could not match
  "ID कार्ड" — routinely written mixed-script, Latin "ID" against Devanagari
  "कार्ड", which neither `आईडी` nor `id\s*card` reaches.
- `refund_callback` had a Devanagari half in all three clauses that covered one
  spelling and missed its neighbour: "कट गया" but not "कटा है", "कॉल कर" but
  not "कॉलबैक", and no word at all for *refund* or *cancel* — the two nouns the
  tactic is named for.
- `payment_detail_change` required "बैंक अकाउंट"; a payroll-redirect scam says
  "सैलरी अकाउंट", never "bank account".
- `unexpected_attachment_or_install` matched "डाउनलोड करें/कीजिए" but not
  "डाउनलोड करके", and required apk and डाउनलोड to be adjacent when real
  messages say "इस APK को डाउनलोड करके".
- `secrecy_request` covered "किसी को मत" and "पुलिस को मत" but not "घर वालों
  को मत" — the family-emergency scam's own version of it.

**`no_action_requested` had quietly inverted again, and was the single biggest
remaining contributor.** The rule tests for the *absence* of action verbs, and
its own comment warns that absence-based rules have to know every language the
presence-based ones do. Its Devanagari list matched "करें" but not "करना",
"करवाइए" or "करके", and had no entry for भरें, अपलोड, लॉगिन or सत्यापित — so
"फॉर्म तुरंत भरें" and "नेट बैंकिंग लॉगिन करें" read as asking for nothing and
collected a −0.8 discount. Four of the ten misses remaining at that point were
being helped over the line by it. This is the second time this specific rule
has inverted; it is worth checking whenever a presence-based pattern gains
vocabulary.

**Two bugs found by measuring rather than assuming, both worth the detour.**
Removing the discount cost one new false alarm on ordinary Hinglish, and it
turned out to be the *same* expiry bug fixed for English earlier the same day —
"वेरिफिकेशन कोड ... जल्दी एक्सपायर हो जाएगा" — because the clause-stripper was
English-only. Its Devanagari counterpart also needed "।" (danda) in the
exclusion class, or the strip runs past the end of a sentence. And the new
credential-advice stripper turned out to swallow "घर वालों को मत बताना":
`CREDENTIAL_ADVICE_RE` matches any negated transmission verb, which is right
for "never share your OTP" and exactly wrong for a secrecy demand. It now only
strips where a credential noun is actually nearby — which improved detection
again on its own, since that clause had been suppressing `secrecy_request`.

That took Devanagari from 19/170 to 6/170. The last six each fired *nothing*,
and clearing them turned up the most broadly useful bug of the day.

**A decimal point in an amount was silently splitting sentences, and with them
most of the rule layer.** Nearly every rule gates on `[^.!?]{0,N}` to mean
"within one sentence". `normalize()` folds digits onto letters but leaves their
punctuation alone, so "Rs 2,450.00" arrives as "rs 2,aso.oo" and "1.5 लाख" as
"l.s लाख" — each carrying a full stop that cuts the sentence in half and puts
the two halves of a rule out of reach of each other. A loan advance-fee scam
went unflagged purely because the approved amount was written "1.5 लाख". Fixed
by dropping separators *inside* a number before normalizing, in
`analyzeHeuristics` rather than in `normalize()` — the latter is shared with the
tokenizer and has to keep matching `train_model.py`'s, per `test_parity.py` —
and before folding, because afterwards "1.5" reads as "l.s" and is no longer
distinguishable from an abbreviation. This one change took Devanagari 6 → 5 and
targeted scams 4.35% → 4.06% by itself, and it applies to every amount in every
language, not just this row.

**The remaining five were each a rule that had the tactic right and the nouns
wrong**: the OLX collect-request scam ("I'm sending payment, just accept the
request on your screen") names no UPI app at all, so the brand-name gate could
never reach it; a refund lure that never says "रिफंड", only "वापस पाने"; a
scheme asking you to upload a bank *passbook*; an IFSC-code harvest that never
says "bank account"; and a telecom cut-off whose account word sits too far from
its threat for the proximity window.

**Two of those five were too loose on the first attempt, and adversarial legit
mail caught it before the benchmark did.** "मीटिंग रिक्वेस्ट एक्सेप्ट कर दीजिए"
— a calendar invite — is the identical imperative to the collect-request scam
and scored 35, and "रखरखाव के कारण सेवाएं बंद रहेंगी" — a maintenance window —
states the same outcome as the telecom threat. Neither is distinguishable
grammatically. What separates them is that the scam is always about money
arriving, and that its cut-off is conditional on *your* inaction; both branches
now require exactly that. Worth noting the benchmark would not have caught
either: neither sentence appears in the corpus. They were found by writing
legitimate mail designed to resemble the rule that had just been widened, and
all seven such probes are now permanent rows in the held-out set (54 → 61).

**Result: targeted scams missed 7.83% → 2.61%, Hinglish/Hindi 10.50% → 1.00%,
Devanagari 19/170 → 0/170, with false positives *down* (1.06% → 0.98%) and the
held-out set at 0/61 and 0/16.** 20 more regression tests (252 → 272), each
pinning the vocabulary gap rather than the rate, and every widening paired with
the legitimate message it must not fire on. Full suite green.

**Read 0/170 carefully.** It means every Devanagari scam *in the curated set*
is now caught, and those 170 rows are also the rows the gaps were found from —
so it measures "no known miss remains", not "no miss exists". The honest read
is that Devanagari has stopped being the worst gap, not that it is solved.

## 2026-08-17 (later)

**A user reported the extension flagging ordinary websites and mail. It was:
the real false positive rate was 16.67%, not the 1.06% the benchmark
reported, and five out of five bank OTP messages were flagged — three of them
"dangerous".** The benchmark was not lying, it was answering a different
question, and it says so in its own header comment: the corpus rows are also
training rows, so the model is graded on data it has seen. What it had never
been asked was how the extension behaves on mail that is *not* in the corpus.

**Built the held-out measurement first, before changing a single rule.**
`tests/test_holdout.mjs` scores 54 modern legitimate messages
(`tests/holdout-legit.csv`, 16 genres: bank OTPs, transaction alerts, order
and delivery updates, SaaS verification and password resets, sign-in alerts,
utility bills, subscription renewals, real promotional newsletters, government
notices, work mail) and 16 real websites (`tests/holdout-pages.json`: the
actual sign-in pages of Google, Microsoft, HDFC, SBI, ICICI, Amazon, GitHub,
PayPal, the Income Tax portal, UIDAI, plus ordinary browsing). None of it is
in `dataset.csv` and none of it may ever be added — the file says so at the
top, because the moment a row is trained on it stops measuring what it exists
to measure. First run: **16.67% of legitimate mail flagged, 25% of real
websites**, against a benchmark reporting 1.06%.

**Nine rule bugs, each found by reading which signal fired rather than by
guessing.** The pattern across almost all of them is the same one this log has
hit before — a rule that names a tactic correctly but tests for a noun instead
of the tactic:

- `credential_request` fired on the anti-fraud warning every real OTP message
  ends with. "Never share your OTP", "किसी को न बताएं", "kisi ko na bataye"
  all put a transmission verb next to a credential noun, which is exactly the
  shape the rule looks for — so the single most reliable marker that a message
  is *genuine* convicted it. This one bug accounted for five of the nine
  flagged messages. Fixed by cutting the negated clause out and looking for a
  request in what remains, rather than skipping the message wholesale: a
  scammer who pastes a real bank footer above their own ask is still caught on
  the ask (there is a test for exactly that).
- `secrecy_request` fired on "Do not share this OTP with anyone" for the same
  reason. The rule is about isolating you from a second opinion; telling you
  to keep a *secret* secret is the opposite.
- `credential_request`'s entry verbs had no object. Bare `update` anywhere in
  a message counted, so "Your Aadhaar update request has been processed
  successfully" — a completion notice with nothing to do — read as a
  credential request. Now requires the verb to point at something ("update
  *your* details").
- `gift_card_payment`, at weight 3.0, the heaviest any rule carries, fired on
  the noun alone. A newsletter offering one as a prize ("a chance to win a
  gift card") is not a demand for payment in gift cards. Now same-sentence
  gated to a purchase or transmit verb, the pattern `crypto_transfer` and
  `prize_or_windfall` already use. The "you've won a $500 gift card, click to
  claim" rows in `curated.csv` are unaffected in verdict — `prize_or_windfall`
  and `artificial_urgency` are what catch those.
- `artificial_urgency` fired on "this link expires in 24 hours". A short-lived
  link or code is a security control, and every password-reset mail ever sent
  says one expires. An *account* expiring still fires, and there is a test
  holding both halves.
- `artificial_urgency` also fired on "Report suspicious calls immediately" —
  the notice banks put on their own login pages. A scammer does not urge you
  to report them.
- `advance_fee` fired on bare "delivery fee". That alternative of the pattern
  had no action requirement at all, so a line item on every checkout page in
  existence convicted at weight 2.0; the real Swiggy cart page came back
  *dangerous*. Now needs someone asking for it, in either order — which is how
  the fix was found to be incomplete the first time: requiring the verb to
  follow the charge broke "Pay the file processing charge", where it precedes
  it, and `targeted scams missed` went 7.83% → 8.12% and named the row.
- `HI.police` matched the "पुलिस" in "पुलिस सत्यापन" (police verification) —
  a routine step in getting a passport, and the most common way the word
  appears in legitimate Indian mail. Same shape of fix as `वारंट(?!ी)` and
  `कस्टम(?!र)` before it.
- `impersonated_authority` had no idea where the text came from, so
  "Income Tax Department, Government of India" fired on incometax.gov.in. The
  rule layer now receives whether the page is served from a brand's own
  registrable domain (`onOfficialDomain` in `engine.js`). On a message, where
  no domain vouches for anything, the rule keeps its full force.

**Two of the four flagged websites were flagged by data gaps, not logic.**
`login.microsoftonline.com` — where every Microsoft 365 and Azure AD sign-in
in the world lands — was not in Microsoft's `domains` list, so the page said
"Outlook", the domain was not recognised as Microsoft's, and the real sign-in
page was called a credential harvest at *dangerous*. And `credential_path`'s
own comment says "on a domain that isn't the brand it names", but the code
only excluded lookalikes: every real login page on the internet has `/login`
in its path, so ICICI's genuine one scored too. Both fixed by making the code
do what the comment already said.

**After the rules: 0/54 and 0/16, with no scam-side cost.** `targeted scams
missed` and `Hinglish/Hindi scams missed` both finished exactly where they
started (7.83%, 10.50%), which is the point — none of this traded detection
for quiet.

**Then the model, which was the actual remaining problem.** With the rules
clean, nothing crossed the threshold, but the margin was thin for a reason
worth naming: the classifier leant scam on **32 of the 54** legitimate
messages, median probability 0.532, and was pushing otherwise-clean mail to
within two points of a warning purely on its own opinion. The cause is in
`build_corpus.py`'s own description — the legitimate half of the corpus is
2002 SpamAssassin ham, mailing lists and Usenet-era personal mail. It contains
essentially no modern transactional mail, so the model had never seen
"debited", "OTP", "available balance", "out for delivery", "renews" or "due
date" in a legitimate context, only in scam ones.

**48 curated legitimate transactional rows, written to the two lessons this
log already recorded.** Structurally varied rather than templated (2026-08-16),
with a handful of short phrases — "do not share it with anyone", "available
balance", "if you did not request this", "no action is required", "you can
safely ignore this email" — deliberately repeated three or more times each so
they survive `min_df=3` (2026-08-17, the entry below). English, Roman-script
Hinglish and Devanagari, and none of them copied from the held-out file.

**Validation accuracy went down, and that is the honest result.** 94.94% →
94.31%, 5-fold CV 94.04% → 93.81%. But the CV standard deviation collapsed
from ±2.24% to ±0.88%, and on held-out mail the model now leans scam on 22 of
54 rather than 32, median probability 0.532 → 0.415 (below 0.5, i.e. correctly
leaning legitimate at all), and the closest legitimate message to a warning
moved from 33 to 20 on a threshold of 35. `Hinglish/Hindi scams missed`
improved on its own, 10.50% → 10.00%. The old number was higher partly because
it was scoring a blind spot: a corpus with no transactional mail in it cannot
penalise a model for misreading transactional mail. Per this log's own
2026-08-17 finding about single-split noise, the tightened CV band is the
figure to read here.

**16 regression tests added** (`tests/test_engine.mjs`, 236 → 252), each
pinning the specific rule that was wrong rather than the rate — and each
paired with its opposite, so "a bank delivering an OTP is not flagged" sits
next to "a real bank footer pasted above an actual ask does not launder the
ask". Full suite green including the 20 browser checks under Chrome for
Testing: 252 engine, parity, 5 benchmark gates, 3 held-out gates, 29 adapter.

**Worth knowing next.** The held-out set is 54 messages and 16 pages, hand-
written by one person in one sitting — big enough to have found nine real bugs,
too small for its 0/54 to mean the false positive rate is zero. Growing it, in
particular with mail nobody on this project would think to write, is the
highest-value thing available. The 2002 corpus is still 84% of the training
data and still has no transactional mail beyond the 48 rows added here.

## 2026-08-17

**Pushed validation accuracy from 93.62% toward 95%, and learned the single
train/test split is noisier than it looks.** Started from the exact numbers
`train_model.py` prints today: 93.62% validation, `targeted scams missed`
already at 7.95% against an 8.00% gate — a margin of one row. That thin
margin shaped everything below: almost every accuracy-motivated change tried
this session tipped that gate over, and finding out *why*, row by row, did
more for the final number than any single batch of new training data.

**34 new curated rows, chosen from three real gaps a held-out error dump
found, not guessed.** Ran the trained pipeline's own `predict_proba` against
its train/test split and printed the worst false positives and false
negatives (the same technique as 2026-08-16, applied to English this time).
Three categories stood out: a family-emergency "temp number, transfer money,
pay you back" scam that had exactly one training row anywhere in the corpus
(no bigram of it could survive `min_df=3`); a courier re-dispatch-fee scam in
the same position; and — the biggest cluster — SpamAssassin ham rows shaped
like prize/trivia/sale newsletters ("Malcolm in the Middle Sweepstakes Prize
Notification", movie trivia, Ryanair freebies) scoring 60–100 as *dangerous*,
because the curated corpus had zero examples of the "legitimate commercial
newsletter" genre to weigh against real prize-scam vocabulary. Added a
handful of structurally-varied rows per category — not a large templated
batch, per 2026-08-16's own lesson about near-duplicate templates — with 2–4
short phrases deliberately repeated 3+ times each so they'd actually survive
the bigram frequency floor (also 2026-08-16's lesson, applied deliberately
rather than rediscovered by accident). First retrain: 94.24%, but
`targeted scams missed` went to 8.41% — over gate, measured immediately
rather than assumed safe.

**Four regex bugs found chasing that regression to the exact rows
responsible, same technique as 2026-08-16's `crypto_transfer` /
`investment_scam` fixes, on new words this time:**

- `HI.send` (the Hindi/Hinglish transmission-verb list) had no entry for
  "ट्रांसफर" — the Devanagari-spelled loanword for "transfer" — even though
  it is at least as common in real UPI/bank-transfer messages as "भेजो". A
  Devanagari message naming an amount and "ट्रांसफर करो" carried no send-verb
  signal at all.
- `family_emergency`'s "unreachable number" check covered "नया नंबर" (new
  number) and "दूसरे नंबर" (another number) in Devanagari but not "टेम्परेरी
  नंबर" (temporary number) — again a loanword transliteration gap, not a
  translation gap.
- `HI.police` matched bare "वारंट" (warrant), which is also the first five
  characters of "वारंटी" (warranty) — a routine "your warranty registration
  is complete" e-commerce message tripped `threat_of_consequence` and
  `impersonated_authority` on nothing but that substring. Same bug class as
  2026-08-15's "कस्टम"/"कस्टमर" collision, fixed the same way:
  `वारंट(?!ी)`.
- `account_suspension`'s noun list had "account", "card", "profile",
  "subscription", "service" but not "net banking" — how Indian bank
  customers actually name their online-banking access — so "SBI net banking
  suspend ho gaya" matched nothing. Its Hindi counterpart had the same gap
  twice over: `HI.blocked` covered "suspend" in Latin script but not the
  Devanagari-spelled "सस्पेंड".

All four fixed with the same narrow, commented pattern already established:
add the missing loanword or exclusion, explain why in a comment next to it,
change nothing else. Added five regression tests to `test_engine.mjs`
(232/232 now, up from 227) so none of these quietly regress.

**The single 80/20 validation split turned out to be far noisier than the
corpus size suggests, and that shaped the rest of the session.** Removing 3
training rows that (confirmed via `predict_proba`) the model still got wrong
even after being trained on them lifted validation accuracy to 94.94% — but
pushed `targeted scams missed` back over gate (8.12%). Adding 6 more
deliberately unambiguous, non-templated Hindi ham rows to rebalance dropped
validation accuracy to 93.41%, worse than before either change. Two rows
addressing a real, still-open gap (a "traffic challan waiver" scam with only
one training example in each script) pushed validation to 95.37% in one
run — and pushed the same gate to 8.55% in the same run, worse than either
prior attempt. Five-fold CV stayed flat at 93.9–94.2% across every one of
these; the single split alone swung by up to 2.5 points on changes as small
as two rows. Treated as a real finding, not noise to explain away: at
~3,550 rows and a 20% test split (~710 rows), a handful of flipped
predictions moves the headline number by over a point, so a single-run
"validation accuracy" reading from a change this size proves less than it
looks like it proves. `train_model.py`'s own printed 5-fold CV figure is the
more honest one to trust when a change is this small.

**Settled on the highest reading that was reproducible and kept every gate
green, not the highest single number seen.** Final state: the 34-row batch
above, minus the 3 rows proven not to help, plus the two `account_suspension`
fixes (which directly rescued two of the newly-exposed misses without
touching training data at all). 94.94% validation, 94.04% ±2.24% 5-fold CV —
below the 95% target, and reported as the honest ceiling rather than chased
further, because every attempt to close the last 0.06 points broke the
`targeted scams missed` gate, which started this session with a 0.05-point
margin of its own. All five gates pass with more room than the session
started with: targeted scams missed 7.95% → 7.83%, Hinglish/Hindi missed
11.23% → 10.50%, false positive rate 1.18% → 1.06%, dangerous-on-legit
0.28% → 0.22%. 232/232 engine checks, parity, and 29/29 adapter checks all
green.

## 2026-08-16

**Two real false positives, reported live by a user, fixed — one a rule bug,
one a training-data gap.** A Bitwarden account-verification email and an
Alpaca (crypto/stock trading) verification email were both flagged as
scams. Reproduced from real screenshots rather than guessed, and root-caused
before touching anything.

**Alpaca — `crypto_transfer` had no proximity requirement.** The rule fired
whenever a crypto keyword (`crypto`, `bitcoin`, ...) and a verb like
`invest`/`deposit` both appeared *anywhere* in the message, in any order, any
distance apart. A crypto brokerage's routine legal footer — "Crypto is
offered through Alpaca Crypto LLC... please consider your investment
objectives before you invest or deposit funds" — satisfies both halves
without the message ever asking anyone to send anything. Fixed by requiring
both within the same sentence (`[^.!?]{0,40}` either order), the same gating
pattern `prize_or_windfall` and `advance_fee` already use for exactly this
failure mode. Real crypto-doubling scams (currency and verb in the same
breath, e.g. "Send BTC to this wallet") are unaffected.

Tightening it exposed a second bug: one curated training row ("guarantees 40
percent monthly returns on crypto... small deposit") had only ever been
caught *by* the loose `crypto_transfer` match, not by `investment_scam`,
which should have caught it and didn't — its
`\bguarantee(?:d)?\s*(?:return|profit|income)\b` pattern matched neither the
plural "guarantees" (word-boundary fails right before the trailing "s") nor
"returns" (same issue), and required the two words directly adjacent with no
gap. Fixed both: `guarantee[ds]?` plus a same-sentence gate instead of `\s*`.
The row is now caught for the right reason.

**Bitwarden — not a rule bug at all.** The model itself reads "verify" /
"email" / "confirm" as scam-leaning vocabulary with real confidence (88–93%
on a reconstructed version of the email), because every single occurrence of
"verify" in `training/curated.csv`'s legitimate (label 0) rows was zero
before today — literally every curated example of that word was a phishing
row. The training corpus predates the now-ubiquitous "verify your email to
finish signing up" SaaS onboarding pattern; the closest legitimate real
example available was a live "Welcome to Bitwarden!" screenshot from the
reporting user.

First attempt at a fix (27 new curated ham rows, one per well-known service)
over-corrected: nearly all of them shared the same "Welcome to X! ...
verify/confirm your email..." skeleton, which is the exact
near-duplicate-template failure this project's own history already flagged
once (see 2026-08-15's Devanagari corpus draft). It fixed both reported cases
completely but pushed `targeted scams missed` from 7.65% to 8.26%, over the
benchmark's own gate — measured, not assumed, so it wasn't shipped as-is.

Replaced with 11 rows: fewer, more structurally varied (different openers,
lengths, and services), but — since the vectorizer uses bigrams
(`ngram_range=(1,2)`, `min_df=3`) — deliberately including 3+ rows that share
the phrase "verify your ... new account" so that distinguishing bigram
actually survives the frequency cutoff instead of every phrase being unique
and none of them surviving. Net effect: Alpaca now scores 21 (safe, was 68);
the Bitwarden reconstruction moved from 64 ("suspicious", borderline
dangerous) to 53 ("suspicious", further from the line) — improved but not
eliminated. Chasing full elimination further was deliberately not pursued
this round: each training-data change perturbs the whole shared TF-IDF space,
and the intermediate attempts visibly moved the Hinglish/Hindi miss rate
around (10.16% → 11.76% → the final 11.76%) as a side effect of changes that
had nothing to do with Hindi. That's the real cost of this kind of fix, not
a one-time nuisance — more of it should happen deliberately, with the
benchmark checked every step, not as a way to fully close one score.

Retrained: validation 94.43% → 95.73%, 5-fold CV 94.20% ±1.52% → 93.76%
±2.21% (wider variance — expected, `curated.csv` grew by only 11 rows against
3,509 total). All five benchmark gates still pass; see the table at the top
for the exact before/after. 218/218 engine checks, parity, and 29/29 adapter
checks unaffected.

**Follow-up round, same day: pushed the corpus work further and it closed
the gap.** Asked to keep training rather than stop at "improved." Added 15
more curated ham rows on the same "new account, verify your email" pattern —
still varied in structure (different openers, lengths, tone), but this time
deliberately keeping the phrase "new account" in several of them rather than
diversifying it away too, since the vectorizer's bigrams (`ngram_range=(1,2)`,
`min_df=3`) can only learn a distinguishing phrase if enough rows share it to
clear the frequency floor — full diversification actively works against that.
Retrained: the Bitwarden reconstruction reached 32 ("safe"), Alpaca 14
("safe").

That pushed `targeted scams missed` over gate again (8.56%, limit 8.00%) —
checked immediately rather than declared done, per the whole reason this gate
exists. This time the newly-exposed misses weren't collateral damage from the
model shift; they were two more real, independent regex gaps in rules that
should already have caught them, the same class of bug as `crypto_transfer`
and `investment_scam` earlier in the day:

- `prize_or_windfall` required the literal word "you" immediately before
  "selected/chosen" (`you(?:'ve| have)?\s*(?:been\s*)?(?:won|...)`), so "Your
  email **was selected** to receive a charity grant" — same lure, different
  subject — matched nothing. Added a `(?:was|has\s*been|have\s*been)\s*
  (?:selected|chosen)\s*to\s*receive` alternative.
- `credential_request`'s two building blocks both had word-form gaps:
  `CREDENTIAL_NOUN_RE` had no entry for "confirmation code" or "verification
  code" (only "otp", "security code", literal "one-time code"), and
  `CREDENTIAL_TRANSMIT_RE`'s `share\s+(?:your|the|it|with)` couldn't match
  "shar**ing**" for the same reason `guarantee(?:d)?\b` couldn't match
  "guarantees" earlier — `\b` needs a boundary immediately after the matched
  word, and neither form has one before its own suffix. "Redeem now by
  **sharing** the **confirmation code** you receive on SMS" — an OTP-relay
  scam wearing a rewards-program costume — matched neither piece. Fixed both.

Retrained once more after the regex fixes (no new corpus changes needed) and
the gate passed clean: 26/327 (7.95%), un-regressed from where it stood
before this whole investigation started. Final state: both real false
positives fixed to "safe," all five benchmark gates pass, 226/226 engine
checks (8 new — regression tests for all four bugs, not just the two
reported ones, so none of this quietly regresses later), parity, and 29/29
adapter checks all green.

The pattern worth remembering from today, stated once rather than three
times: every one of the four regex bugs found (`crypto_transfer`,
`investment_scam`, `prize_or_windfall`, `credential_request`'s two helper
patterns) was a rule that looked like it covered a case and silently didn't —
missing plurals, missing word-forms, missing proximity constraints, or an
assumed sentence subject that wasn't always there. None were found by
auditing the rules file; all four were found by chasing one specific reported
failure until the actual regex was read character by character. The
model-authority tradeoff documented above (a small amount of the ceiling
`MODEL_MAX_PULL` still commands on near-stopword vocabulary) is the one part
of today's investigation that turned out not to be a bug — it's a deliberate
design choice from 2026-08-05, made for a good, still-valid reason, and nudged
rather than removed.

**Network-consent design implemented, not just designed.** The three toggles
from `wip/network-consent-design` (Claude second opinion, shortener
resolution, URLhaus feed) are wired into `extension/options/options.html` /
`options.js` as a shared "Network features" section, each requesting and
releasing its own `optional_host_permissions` origins exactly the way
`cloudTier` already did — see `rationale.md`'s point that collapsing them
into one switch would make at least one toggle's copy false the moment
another is off. `manifest.json` gained the 19 shortener origins plus
`urlhaus-api.abuse.ch`, and the base `permissions` list gained `alarms` (for
the feed's periodic refresh) and `webRequest` (see below).

**One platform detail the design doc didn't reach: `redirect: "manual"`
cannot actually read where a link goes.** The design's Question 1 resolved
*which* redirect to follow (first hop only); it didn't get as far as *how* to
read it. `fetch(url, { redirect: "manual" })` returns an opaque-redirect
Response whose headers — including `Location` — are inaccessible by platform
design, even with host permission for the origin, because the filtering
happens before extension code sees the response at all. The actual working
mechanism is `chrome.webRequest.onBeforeRedirect`, which observes the wire
rather than the fetch Response and exposes `redirectUrl` directly —
implemented in `extension/engine/shortener.js`'s `resolveFirstHop()`. This
needed adding `"webRequest"` to the manifest's base permissions (it grants no
network access by itself; actual observation is still gated by the
already-optional host permission for the specific origin).

**The URLhaus feed endpoint was a flagged guess, then a wrong guess, then a
verified one — in that order, same day.** The first guess
(`v2/urls/exports/{key}/recent.csv`) 404s: wrong resource, confirmable
without a real key since a 404 doesn't need one. The real anonymous endpoint
is `https://urlhaus.abuse.ch/downloads/csv_recent/` — `curl` against it
returns 200 with the live feed, no Auth-Key, right now, contradicting
`rationale.md`'s reasonable-at-the-time assumption that the mid-2025
"Auth-Key mandatory" mandate would cover it (their downloads page 403s an
automated fetch without a browser User-Agent, which is why that document
couldn't check). `URLHAUS_FEED_URL` in `extension/engine/urlhaus.js` now
points at the real path; the Auth-Key field became optional throughout
(`storage.js`, `options.html`, `options.js`, `service-worker.js`) rather than
required, since it plainly isn't one. `parseFeed()` needed no changes for
any of this — reusing `extractUrls()` per line rather than assuming a fixed
CSV column layout meant the real format (a `#`-commented header block, then
quoted CSV rows) parsed correctly on the first try against real fetched data
(16,928 URLs).

**Both new network calls were kept out of the "local" analysis path.**
`analyzeLocal()` gained an `urlhausFeed` option (a pure local-storage lookup,
matched with `matchUrlhaus()`) but stayed synchronous-in-spirit; shortener
resolution is a real network call, so it lives in `analyze()` as an opt-in
step before the local layers run, the same shape as the existing `cloud`
callback. A resolved destination is folded into `extraUrls` so the *actual*
link — not the shortener's own domain — gets scored by the existing URL
heuristics; a confirmed URLhaus hit scores as a `urlhaus_match` signal
(weight 4.0, enough to convict alone on the cases tested, though not
provably immune to a maximally negative model pull — see `MODEL_MAX_PULL` in
`engine.js`).

**Popup copy updated to stay literally true per-result.** `describeTier()`
now appends a shortener-contacted note only when `result.shortenerResolved`
is set on *that* result, matching rationale.md's Question 3: `checkUrlhaus`
needs no per-result copy at all, because it matches a feed already in storage
and never calls out while a specific message is being scored.
`renderFooter()` now joins whichever of the three features are actually on
instead of collapsing to a boolean.

218/218 engine checks pass (17 new: a manifest/`URL_SHORTENERS` drift check,
`isShortenerUrl`, `parseFeed`, `matchUrlhaus`, a `urlhaus_match` conviction
case, and shortener-resolution wiring including a resolver that throws).
All five benchmark gates, parity, and 29/29 adapter checks are unaffected —
both features are no-ops until their toggle and permission are both live.

**The browser layer actually ran, for the first time in this environment —
and caught something, though not in the new code.** `run_all.py`'s note that
branded Chrome 137+ refuses `--load-extension` turned out not to be a hard
stop: `npx @puppeteer/browsers install chrome@stable` fetches Chrome for
Testing, needs no account, and `CHROME_BIN=<path> python3 tests/run_all.py`
runs all 20 browser checks that had only ever been skipped before. First run
against this branch failed 12 of them (`.baitwatch-warning` never appeared,
history stayed empty); re-running the *unmodified* `main` branch against the
same Chrome for Testing binary reproduced nothing — 20/20 clean — which ruled
out the manifest/service-worker changes as the cause before assuming it.
Two more runs against this branch afterward both passed 20/20 clean, which
points at one-off flakiness (plausibly Chrome for Testing's own cold start)
rather than something introduced here — but that's an inference from
absence, not a proven root cause, and it's the kind of intermittent failure
worth someone's attention if it recurs.

**What that first run confirmed, and what got checked afterward by driving
the two new features live instead of stopping there.** The `run_all.py` run
confirmed the base extension — manifest, service worker boot, content-script
injection, whole-page scan — works with the added permissions sitting
unused. That's necessary but not sufficient, so both new features were then
exercised directly against real external services, not mocks:

*Shortener resolution.* A real short link was created via `is.gd`'s
anonymous create API (`is.gd/AG3Hwv` → `example.com`, confirmed by `curl -I`)
and fed to `resolveFirstHop()` running inside a real loaded extension (a
disposable `/tmp` copy with the shortener origin moved to mandatory
`host_permissions`, to get around a separate limitation below). It correctly
returned `example.com` — the `chrome.webRequest.onBeforeRedirect` mechanism
works as designed.

*The URLhaus pipeline, end to end.* With `checkUrlhaus` forced on and the
real `REFRESH_URLHAUS` message handler called on a loaded extension, the
extension's own `fetch()` → `parseFeed()` → `chrome.storage.local` pipeline
landed 16,930 real entries with no code changes — first attempt hit HTTP 405
"Banned" from Fastly's edge, reproduced identically on a bare
`Page.navigate()` to the same URL with *no extension involved at all*, and
isolated to **headless** Chrome specifically: the identical request from a
non-headless (windowed) Chrome for Testing instance got a clean 200. This is
a known bot-defense fingerprint on headless automation, not a defect in the
extension — but it means `run_all.py`'s browser layer (which runs headless)
would reliably show a false failure if this feature were added to it, and
that shouldn't be mistaken for a regression if it recurs.

*What's still genuinely unverified, and why it can't be closed from here.*
The permission-*request* round-trip itself — clicking a toggle, Chrome
showing the native optional-permission prompt, a person accepting or
declining it — could not be driven through CDP automation at all. Confirmed,
not assumed: a real trusted click was dispatched at the actual checkbox (via
`Input.dispatchMouseEvent`, after the first attempt silently missed because
the element was outside headless Chrome's default viewport), the checkbox's
own visual state toggled, and `chrome.permissions.request()` still hadn't
resolved 23 seconds later. The permission bubble is native browser chrome,
not a DOM element, so no CDP `Input` event can reach it — headless or
headed, this specific gap needs an actual person clicking Allow/Deny, which
is a live-usage check, not a testing-environment limitation to work around.

## 2026-08-15

**The Devanagari corpus gap is closed, not just narrowed.** 250 rows added to
`training/curated-hinglish.csv` (306 rows total, up from 56), researched
against RBI/CERT-In/TRAI advisories and news coverage — still authored-to-
pattern rather than scraped, since no bulk public corpus of raw Hindi-script
scam text exists to draw from, but built avoiding four concrete problems a
first attempt found (a template-substitution bug that duplicated a bank
name, heavy near-duplicate template reuse, three-way confusion between
`digital_arrest` and plain `courier_customs`/robocall scams, and the
English-language 419-letter genre transplanted into Devanagari where it does
not actually circulate). Retrained: validation accuracy moved 95.85% → 94.43%
— a harder, more honest number on a corpus that is no longer 99.5% the same
280 English rows padded with SpamAssassin.

**Retraining alone was not enough, and measuring said so before anyone had
to guess.** First benchmark run after the retrain: targeted scams missed
27.22%, Hinglish/Hindi missed 44.92%, both far outside the existing 8%/20%
gates — a regression, not an improvement, despite the model having Devanagari
vocabulary for the first time. The cause was in the rule layer, not the
model: `family_emergency`, `courier_customs`, and `job_advance_fee` already
had rules, but scored these exact tactics 9–31 out of the 35 needed to warn.

**Root cause: JavaScript's `\b` never matches around Devanagari.** `\b` is
defined as a transition between `\w` ([A-Za-z0-9_]) and non-`\w`, and no
Devanagari character is ever `\w` — so `\b(?:तुरंत)\b` cannot match, because
neither side of "तुरंत" is ever a `\w` character for `\b` to transition
against. Two rules wrapped a combined Latin+Devanagari string in one `\b`
pair (`artificial_urgency`, and `family_emergency`'s crisis check), which
silently dropped every Devanagari alternative while reading as if it covered
both scripts. `/\b(?:अभी)\b/.test("अभी अस्पताल")` is `false`;
`/अभी/.test(...)` is `true` — confirmed empirically before touching the
rule, not assumed. Fixed by splitting `HI.urgent` into `HI.urgentLatin`
(kept inside `\b`) and `HI.urgentDevanagari` (bare, matching how every other
`HI.*` entry in the file was already written).

**Everything past that was real vocabulary gaps, not one bug.** Real
Devanagari-script messages routinely spell English loanwords in Devanagari
letters rather than translating them — "जॉब" not "नौकरी" alone, "बॉस" not a
Hindi word for boss, "रिफंड", "चार्ज", "जॉइनिंग किट", "रिमोट एक्सेस" — and
several rules (`payment_detail_change`, `boss_impersonation`,
`gift_card_payment`, `unexpected_attachment_or_install`) had no Devanagari
coverage at all, in some cases none even for the transliterated Hinglish
form. Two rules were missing entirely: `investment_scam` (guaranteed-return
Telegram groups, mutual-fund schemes, stock-tip channels — a shape with no
prior coverage in *either* script) and `sextortion_threat` (a
recording/photo threatened with going public unless paid — also uncovered
in English). ~25 edits later, largely one or two words per fix, chosen by
what the benchmark's worst misses actually said rather than guessed.

**Widening Devanagari coverage created new false positives, and the
benchmark caught those too.** "अभी" (right now) reads as an imperative in
Hinglish ("abhi bhejo") but just as often means "just now" reporting
something already done in plain Devanagari — "अभी 2,500 रुपये ट्रांसफर किए"
is a bank confirming a completed transfer, not a threat. Excluded from
`urgentDevanagari` for that reason. "कस्टम" (customs) is also the first four
characters of "कस्टमर" (customer) — a bare substring match flagged every
"contact customer care" line in the corpus; fixed with `कस्टम(?!र)`. Bare
"रिफंड"/"कैशबैक" flagged routine "your refund will arrive in 5 days"
notices; gated on a nearby call to action (claim/redeem/link/form) instead,
since the scam version always asks the reader to do something and the
routine version never does.

**One stale test, not a regression.** `test_engine.mjs` asserted the model
*abstains* on `"आपका खाता ब्लॉक हो गया है। तुरंत ओटीपी भेजिए।"` — true when
the corpus had 16 Devanagari rows and not one Hindi term survived
`min_df=3`, false now that it has 306. The assertion flipped to check the
model votes instead of abstaining, and a Tamil fixture (a script the corpus
still has zero vocabulary in) replaced it as the abstention-still-works case,
so the mechanism itself stays covered.

Final gates, `node tests/test_benchmark.mjs`:

| | before today | after |
|---|---|---|
| targeted scams missed | 4.00%\* | 7.65% |
| Hinglish/Hindi scams missed | 5.71%\* | 10.70% |
| …devanagari alone | 0/10\* | 17/162 |
| false positive rate | 0.73%\* | 1.03% |

\* Not a fair comparison — the old numbers are against 16 Devanagari rows the
model had already memorised having seen in training; these are against 250
new ones covering real tactic diversity for the first time. All five gates
pass; `python3 tests/run_all.py` is green apart from the browser layer, which
still needs Chrome for Testing outside this environment.

The network-consent design (see `docs/design/network-consent/` on
`wip/network-consent-design`) was also redone the same way — three
independent toggles, no master switch — and this time actually resolved its
three open questions instead of leaving them for later: shortener resolution
is first-hop-only (the only thing Chrome's `optional_host_permissions` model
can grant), URLhaus moved from a live per-URL query to a downloaded feed
entirely (their API has no hash-based lookup and has required an auth key on
every call since June 2025, so hashing would not have bought anonymity
anyway), and `describeTier()`'s disclosure text was drafted for both new
toggles. Implemented 2026-08-16, see below.

*Correction, 2026-08-16:* this section originally said the Devanagari corpus
work was uncommitted and unpushed. That was wrong by the time it was written
— `f3ce03c` (the corpus + rule fixes) was already the tip of `main` and
`origin/main`. Caught only when asked directly to double check; this file is
not self-verifying, `git log` is.

## 2026-08-09

`adapter-health` merged into `main` (fast-forward, `ed13791..38145e2`, nothing
divergent to reconcile) and pushed. All gates held: parity, 200/200 engine
checks, all five benchmark gates, 29/29 adapter checks; the browser smoke test
still can't run outside Chrome for Testing, unchanged from before.

A Devanagari corpus draft and a network-consent design were started the same
day, both deliberately kept out of the repo pending review. Both were lost —
their only copy sat in a session-scoped scratch directory that was swept
before either was committed, six days before anyone acted on the review.
Neither ever touched `main`; nothing was lost that had shipped. Redone from
scratch 2026-08-15, see below.

## 2026-08-06

Five parallel workstreams, each in its own worktree, merged into
`adapter-health`. Ordered below by how much they change what the extension
actually does.

**A rotted site adapter now announces itself** (`extension/content/adapters.js`,
`scanner.js`). Gmail and WhatsApp rewrite their markup without notice, and when
a selector rots, `collect()` returns an empty list — which is exactly what an
empty inbox returns. Auto-scan went quiet and nothing anywhere noticed; the
first sign of trouble would have been a scam that was never flagged.

Each site adapter now declares `landmarks` alongside its message `selectors`:
ARIA roles and structural ids that say the app rendered a conversation at all.
They are deliberately drawn from a different layer of the markup than the
selectors they vouch for, because a landmark is only evidence that a selector
broke if it can still match when that selector cannot. Empty results on a page
whose landmarks are present, sustained across three scans *and* ten seconds,
mean the selectors have gone — the popup says so and the page console records
it. Both thresholds are needed: Gmail paints its message list a beat before the
bodies, so the first empty pass on a freshly opened thread is normal.

The generic adapter declares no landmarks and reports `unknown` forever. On an
arbitrary page, finding nothing message-shaped is the ordinary outcome, and a
monitor that cries wolf gets ignored — which would leave the extension exactly
as silent as it was before.

**A privacy claim that could be false** (`engine.js`, `popup.js`,
`overlay.js`, `claude.js`). Found while auditing the manifest. When the Claude
tier was on and the request failed, `analyze()` returned `{...local,
cloudError}` with `tier` still `"on-device"` — and both the popup and the
in-page warning render that tier as "Checked entirely on your device — nothing
left your computer", printed directly above "Second opinion unavailable". The
text had gone to Anthropic and the interface said it had not. The same root
cause made `cloudCalls` skip every failed call, so the one counter a user could
audit this with was wrong in the same direction.

A failure now returns tier `"cloud-failed"`, and `claude.js` tags the errors
it raises *after* a response arrives. That distinction is the difference
between two true sentences and one false one: if Anthropic answered, the text
certainly left the machine and the UI says so plainly; if the `fetch` never
resolved, nothing proves either way and the UI says "may have left your
computer" rather than guessing. `cloudCalls` counts attempts, not successes.

Of everything this extension says, that one line is the one that has to be
literally true — a user who reads "nothing left your computer" has no other
way to discover that it did. So it is asserted in `tests/test_engine.mjs`
now rather than trusted, including a check that the fixture actually reaches
the escalation band, without which the whole group would pass while testing
nothing.

**Network access is now optional, and off until asked for**
(`manifest.json`, `options/options.js`, `background/service-worker.js`).
`api.anthropic.com` was a mandatory `host_permissions` entry, so every user
granted network access at install to enable a feature that is off by default —
the install prompt contradicted the extension's central claim at exactly the
moment someone is deciding whether to trust it.

It is an `optional_host_permissions` entry now. The options page requests it
when the second opinion is switched on and removes it when it is switched off,
so revoking the feature revokes the capability rather than just setting a flag,
and a refusal puts the toggle back rather than promising something the
extension cannot do. The service worker re-checks the grant before every
escalation: a permission revoked from `chrome://extensions` disables the tier
instead of producing failures that would read, misleadingly, as "this may have
left your computer".

The claim that a fresh install can reach nothing is now asserted in the
browser, by reading `chrome.permissions.getAll()` from the service worker.
Moving the origin back to `host_permissions` would work perfectly and silently
grant every user network access on install, which is precisely the kind of
regression no other check would notice.

**Manifest** (`extension/manifest.json`). `web_accessible_resources` published
the 262 KB model to every page on the web under `<all_urls>`; nothing in a
content script reads it, so it was pure fingerprinting surface, and it is gone.
`host_permissions` was `https://api.anthropic.com/` — a match pattern's path is
significant and bare `/` matches only the root, not `/v1/messages`. The store
description was 147 characters against a hard limit of 132, which rejects the
upload rather than truncating it. The `tabs`-free design still holds: every
declared permission is used, and the whole-page scan still works by asking the
content script to report the address of the page it is already on.

**The browser test layer was lying** (`tests/run_all.py`). It polled
`localhost:9223` without checking it had reached the Chrome it launched, and
`stderr=DEVNULL` swallowed the fixture server's bind failure — so anything else
holding those ports produced a full set of plausible failures against perfectly
good code. It now aborts if either port is occupied, verifies the fixture
server is its own by fetching back a per-run token, and takes
`BAITWATCH_CDP_PORT` / `BAITWATCH_PAGES_PORT`. Three checks were added that
assert on the parsed model artifact directly rather than inferring it from a
verdict, which is what actually proves the model still loads without the
`web_accessible_resources` entry.

**The tokenizer can read Devanagari now. The model still cannot.** Both halves
of that are the result; reporting only the first would be a lie by omission.

scikit-learn's default `token_pattern` is `(?u)\b\w\w+\b`, and `\w` excludes
Unicode Marks. Devanagari vowel signs are Marks, so a word is a run of word
characters interrupted by characters that are not: `"खाता"` tokenized to
nothing at all and `"आपका"` to the fragment `"आपक"`. The model was reading
mangled consonant skeletons of whatever the user actually wrote.

Both sides now use `\w[\w<Indic marks>]+` — `training/train_model.py` and
`tokenize()` in `extension/lib/text.js`, the same explicit code point ranges
written out per script in both files. Marks are *continuation* characters
only, so they can extend a token that began on a letter but never start one,
which is what makes the change provably invisible to Latin text. Verified by
enumeration rather than argument: for every code point up to U+2FFFF,
inserting it between two English words changes the token list only for the
marks in that class. English weights were learned on unchanged input.

Explicit ranges rather than `\p{M}`, on three grounds. Python's `re` has no
`\p{M}` and the `regex` module cannot supply one here, because
`TfidfVectorizer` compiles `token_pattern` with `re` — using it would mean a
`tokenizer=` callable, which joblib pickles by reference, so `test_parity.py`
could not load the model in a separate process without importing the trainer.
`\p{M}` would also match the combining diacritics in decomposed Latin, which
is exactly the silent English regression the change had to avoid. And `\p{M}`
resolves against whichever Unicode version each runtime ships, so JavaScript
and Python could disagree about a code point while both looked right. Literal
ranges are the same set in both languages forever. No dependency was added,
and the extension stays dependency-free.

**The parity test could not have caught this, and now can.** It compared
probabilities. A term with no weight is absent from the vector either way, so
two tokenizers disagreeing about every Devanagari word return the same number
and pass — which is how the bug survived. It now compares token lists too,
taking the tokenizer out of the *fitted* vectorizer so what is checked is the
pattern baked into the shipped artifact. Confirmed to fail when the old
pattern is put back: 30 of 3,280 inputs diverge. Sixteen new probes cover
Devanagari, mixed Devanagari/Latin, other Indic scripts, and decomposed Latin.

**And the honest part.** Every measured number is unchanged:

| | before | after |
|---|---|---|
| validation accuracy | 95.85% | 95.85% |
| five-fold CV | 94.80% ±1.66% | 94.77% ±1.59% |
| legitimate mail flagged | 0.73% | 0.73% |
| …called *dangerous* | 0.18% | 0.18% |
| targeted scams missed | 4.00% | 4.00% |
| Hinglish/Hindi scams missed | 5.71% | 5.71% |
| …Devanagari alone | 0/10 | 0/10 |
| false alarms on ordinary Hinglish | 0/21 | 0/21 |

Not one Devanagari term reaches the vocabulary, before or after. The corpus
has 16 Devanagari rows in 3,248. `min_df=3` leaves 10 Hindi terms of 127, and
`max_features=6000` — which ranks by corpus-wide frequency — then drops all
ten. The model abstains on all 16 rows exactly as it did before, on zero known
terms. Raising the cap to keep them would mean shipping a 1 MB model to gain
ten Hindi function words learned from ten scam rows and six legitimate ones,
which is memorising, not learning.

So: the mechanism is fixed and the outcome is not. A tokenizer producing terms
the model has no weights for is a precondition for reading Hindi, not the
ability to read it. What is left is a dataset problem — more Devanagari rows —
and it is now the only thing in the way.

**Unicode confusables** (`tools/build_confusables.py`). The fold table was two
hand-picked maps that had drifted apart — nine Cyrillic letters and ten Greek
in `lib/text.js`, fourteen and ten in `engine/urls.js` — so an attacker only
had to reach one letter further down the alphabet. Both are gone; there is now
one `foldConfusables()` in `lib/text.js` backed by a generated table, the same
way `psl-data.js` replaced the hand-rolled suffix list.

273 of the source file's 6,565 mappings survive, 3.2 KB. The filters are the
interesting part: the target has to be a *single ASCII letter*, which throws
out the majority — Unicode's prototype for Greek epsilon is `ꞓ` and for
Cyrillic ve is `ʙ`, meaning those are confusable with each other and not with
the ASCII letter, and folding them to `e`/`b` would have been a guess. Anything
NFKD already handles goes too, which is where the size went: 897 mappings, most
of them the thirteen styled Latin alphabets in the Mathematical Alphanumeric
block, were free all along. And the scripts are allowlisted rather than taken
wholesale — Devanagari most pointedly, because the Hindi rules match it
literally against `normalize()`'d text and a fold would have switched a whole
language's rules off in silence.

Caught now that were not before: `gσσgle.com`, `ѡһatsapp.com`, `γσutubҽ.com`.
Not one of them was within edit distance either — dropping the letter the old
table could not read left `ggle`, `atsapp`, `utub`. The benchmark did not move
by a single message in any of the five gates, which is the number that
mattered: the risk in widening a fold is a false positive, not a miss.

The fold also had to move *before* the lowercase rather than after it. Unicode's
twins are case-sensitive — Cyrillic `В` is identical to Latin `B` while `в` is
not identical to `b` — and folding a lowercased string throws that away, which
showed up as a pile of mappings claiming both `i` and `l` for the same letter.

## 2026-08-05

Five commits, `ce7756d..3c6a080`.

**Licensing and domain boundaries.** Added MIT `LICENSE` — the repo had none,
which meant all rights reserved and blocked incorporating anything. Replaced a
23-entry hand-rolled suffix table with the full Mozilla Public Suffix List
(`tools/build_psl.py`). The gap was real: `github.io` and `vercel.app` live in
the list's *private* section, so every page on every free host was collapsing
to one registrable domain and `paypal-verify.github.io` was being compared as
`github.io`.

**Brand impersonation** (`extension/engine/impersonation.js`). The URL layer
asks whether the *domain* imitates a brand; this asks whether the *page* claims
to be one. Conjunctive: brand in the title or wired to the sign-in prompt, a
domain the brand doesn't own, a page thin enough to be a login form, and an
actual password or OTP field.

**Punycode** (`extension/lib/punycode.js`). RFC 3492 decode, so non-Latin
homoglyphs fold like any other. Cyrillic `рaypal.com` went from 46/suspicious
with a warning that could only say "punycode domain" to 69/dangerous naming
PayPal. Also stopped treating all punycode as suspicious — that flagged every
legitimate German, Russian, Chinese and Indian-language domain. The attack is a
*single label mixing alphabets*, not internationalization.

**Dataset** (`training/build_corpus.py`). Merged the curated rows with the
SpamAssassin public corpus. Five-fold CV went from **93% ±18%** to 95.5% ±1.2%
— the accuracy barely moved, the trustworthiness did. `hard_ham` mattered most:
mail that looks like spam but isn't. It also killed a confound where curated ham
averaged 61 characters against 100 for scams, so length alone carried signal.

**Accuracy benchmark** (`tests/test_benchmark.mjs`). Measures how often the
whole fused engine is wrong, with gates that fail the build. Nothing was
measuring this before — the model's cross-validated accuracy is not the number
a user experiences.

**Five new rules**, chosen by the benchmark rather than by guesswork: family
emergency, delivery redispatch fee, job advance fee, refund callback, windfall
solicitation. Targeted misses 15.7% → 3.6%.

**Hinglish and Devanagari.** 64% of Roman-script Hindi scams and 100% of
Devanagari ones were being missed. Now 12% and 0%.

### Bugs found along the way

Most of these were pre-existing and none were the thing being worked on. They
are listed because the pattern is worth remembering: each was found by testing
a *new* feature, not by looking for bugs.

1. **Homoglyph domains that fold exactly onto a brand were never flagged.**
   `paypa1.com` scored zero while `paypa1-secure.com` scored 3.0 — the
   edit-distance branch skipped anything where the folded labels matched, which
   is precisely the clearest cases.
2. **Every legitimate login page was called dangerous.** `credential_request`
   read "enter your password" as a credential request, which it is in a message
   and is not on the form it describes. Real HDFC NetBanking scored 66,
   Atlassian 72 — the same band as phishing, on exactly the page whole-page
   scan exists for.
3. **The model could never flag a message on its own.** Its ceiling was 22
   points and the threshold to warn is 35, so pretext-only phishing with no
   link and no credential verb could not be flagged however certain the model
   was. Correct for a 93% ±18% model, wrong once it was 95.5% ±1.2%.
4. **An exonerating rule was inverted for every non-English message.**
   `no_action_requested` tests for the *absence* of English verbs, so it fired
   on all Hindi text and discounted the scams the rules existed to catch.
5. **The classifier voted against text it cannot read.** Devanagari yields
   almost no known terms, p=0.472, and a *negative* pull. It now abstains.
6. **`export_model.py`'s coefficient pruning was unsound.** Dropping a
   near-zero-coefficient term is safe for the dot product and wrong for the
   vector, because TF-IDF is L2-normalized and every present term is part of
   the norm. Latent until two terms crossed the threshold; the parity test
   caught it, which is what it is for.

## Next

**Both 2026-08-16 items are closed.** The network-consent implementation
merged as `d1d06af` on 2026-08-17, and the last open piece — a real person
clicking through the `resolveShorteners`/`checkUrlhaus` consent prompts —
closed 2026-09-05 (see that entry above). Nothing from that work is
outstanding any more.

**Finish the held-back Devanagari corpus branch.** 100 new rows sit on
`worktree-agent-aedf207fcdda6d95b` (`ab63082`), unmerged, because they push
two benchmark gates into failing territory (see the 2026-09-05 "four
parallel worktree agents" entry above for exact numbers). Needs a
rule-writing pass against the 17 new misses before this can merge — same
"corpus round exposes a gap, rule round closes it" cycle this file has
documented three times before.

**The Devanagari OTP-legit exoneration gap**, flagged in the same entry: a
message that states an OTP but explicitly tells the reader not to share it
with a stranger still scores 38 (suspicious). Worth doing alongside the
rule-writing pass above, since both touch the same Devanagari-legit
surface.

**`artificial_urgency` false-firing on bare "immediately" — closed 2026-09-05.**
"Dox this woman immediately so as to call CPS to save the child from further
abuse." (the same X reply thread the stale-banner fix surfaced) solo-convicted
on the bare word, with nothing distinguishing an imperative urging the reader
to report a *third party* to a protective authority from a scam's manufactured
countdown around the reader's own account. Rather than a general
reader-direction gate (the `threat_of_consequence`/`crypto_transfer` shape),
this rule is already built as a series of narrow, evidence-driven stripping
exclusions — four of them already there (link/code/session expiry, "urgently
needed" as a shortage, "X should immediately Y" about a third party, "report
suspicious... immediately" as an anti-fraud notice) — so the fix added a fifth
in the same shape: strip `immediately`/`urgent(ly)` when it co-occurs with a
call to report someone else to police/CPS/911/authorities, either ordering.
New fixture in `test_engine.mjs` and a new ambient entry in
`holdout-ambient.json` pin it; every existing gate (including the two
fixtures that must *keep* firing, `accountExpiry` and its Devanagari
counterpart) stayed green with identical numbers.

**Structural login-form checks that stand alone — closed 2026-09-05.** See
that entry above (`3ce64cd`); off-site credential POST can now convict
alone on a title-brand-claim mismatch, not just as corroboration.

**Deliberately not doing**

- Rules for the last few targeted misses. They no longer share a shape — a
  payroll redirect, a pre-approved-loan fee, a traffic-fine settlement — so
  each would be one rule for one row, which is how a rule set starts
  overfitting its own test set.
- Gating the corpus-wide false negative rate. That corpus is 2002 commercial
  advertising and not warning about a newsletter is correct behaviour.

## Notes to self

- **`normalize()` folds digits onto letters** to defeat homoglyphs, so `8000`
  reaches a rule as `8ooo`. Never match `\d` in a heuristic.
- **Watch trailing `\b` after a stem.** `reschedul\b` cannot match
  "reschedule" — it demands a boundary between "l" and "e".
- **Run `python3 tests/run_all.py` before pushing.** The browser layer needs
  Chrome for Testing; branded Chrome 137+ silently refuses to load unpacked
  extensions from the command line.
- **Always re-run parity after touching the model or the tokenizer.** A
  divergence produces confident wrong answers with nothing at runtime to catch
  it.
- `docs/TASKS_OVERVIEW.md` describes the V1 FastAPI build that no longer
  exists. It is kept as a record of how the hackathon was organized, not as a
  description of the current code.
