# Progress

Where the project stands and what is worth doing next. For how it works, see
the root [`README.md`](../README.md); this file is the running log.

Last updated **2026-08-15**.

## Current state

| | |
|---|---|
| Repo | `github.com/sreekarseera/baitwatch` (public, MIT) |
| Archive | `github.com/sreekarseera/baitwatch-archive` (private, the original 32-commit history) |
| Detection | 24 heuristics + URL analysis + brand impersonation + on-device classifier |
| Model | 3,498 rows, 94.43% validation, 94.20% ±1.52% five-fold CV, 6,000 terms, 264.5 KB |
| Tests | 201 engine checks, model parity (tokens + predictions), 5 accuracy gates, 29 adapter checks, 20 browser checks |

Measured accuracy, from `node tests/test_benchmark.mjs`:

| | rate |
|---|---|
| legitimate mail flagged | 1.03% |
| …called *dangerous* | 0.34% |
| targeted scams missed | 7.65% |
| Hinglish/Hindi scams missed | 10.70% |
| …devanagari alone | 17/162 |
| false alarms on ordinary Hinglish | 1/119 |

Validation accuracy and false-positive rate both moved against 2026-08-06's
numbers — worth reading before assuming a regression. Both are true at once:
the corpus is harder now (250 more Devanagari rows, most of them scam
messages the old 16-row set couldn't represent), and the whole engine catches
far more of them than before. See 2026-08-15 below.

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

**Not yet done:** none of this is committed past the
`wip/devanagari-corpus-draft` branch, and nothing is merged into `main` or
pushed. The network-consent design (see `docs/design/network-consent/` on
`wip/network-consent-design`) was also redone the same way — three
independent toggles, no master switch — and this time actually resolved its
three open questions instead of leaving them for later: shortener resolution
is first-hop-only (the only thing Chrome's `optional_host_permissions` model
can grant), URLhaus moved from a live per-URL query to a downloaded feed
entirely (their API has no hash-based lookup and has required an auth key on
every call since June 2025, so hashing would not have bought anonymity
anyway), and `describeTier()`'s disclosure text was drafted for both new
toggles. Still design-only — nothing wired into `extension/options/`.

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

**Merge `wip/devanagari-corpus-draft` into `main`.** Done and gate-passing
(see 2026-08-15) but not yet merged or pushed — the corpus, retrained model,
~25 heuristic-rule fixes, and one updated test all sit on the branch as
uncommitted or branch-local work. Nothing has touched `main`.

**Implement the network-features consent UI.** The design is finished (see
2026-08-15 and `docs/design/network-consent/` on `wip/network-consent-design`)
down to the toggle structure, storage keys, permission origins, and
`describeTier()` disclosure text — what's left is wiring it into
`extension/options/`, plus actually building shortener resolution
(first-hop only) and the URLhaus downloaded-feed check behind it. Pure
implementation at this point, not design.

**More Devanagari rows, if the miss rate needs to come down further.**
17/162 Devanagari scams are still missed after today's pass — well inside
the 20% language-specific gate, but real. What's left doesn't cluster the
way today's gaps did (each remaining miss is closer to a one-off phrasing
than a missing category), so the next win is more likely in the corpus than
in another rule-writing pass — the same "more Devanagari rows" conclusion
this file reached before 2026-08-15, just at a smaller remaining gap.

**Smaller, when convenient**

- Structural login-form checks that stand alone. Off-site credential POST is
  currently only counted as corroboration for an impersonation finding,
  because hosted auth providers do it legitimately.

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
