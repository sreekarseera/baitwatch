# Progress

Where the project stands and what is worth doing next. For how it works, see
the root [`README.md`](../README.md); this file is the running log.

Last updated **2026-08-06**.

## Current state

| | |
|---|---|
| Repo | `github.com/sreekarseera/baitwatch` (public, MIT) |
| Archive | `github.com/sreekarseera/baitwatch-archive` (private, the original 32-commit history) |
| Detection | 21 heuristics + URL analysis + brand impersonation + on-device classifier |
| Model | 3,248 rows, 95.85% validation, 94.77% ±1.59% five-fold CV, 6,000 terms, 262 KB |
| Tests | 200 engine checks, model parity (tokens + predictions), 5 accuracy gates, 29 adapter checks, 18 browser checks |

Measured accuracy, from `node tests/test_benchmark.mjs`:

| | rate |
|---|---|
| legitimate mail flagged | 0.73% |
| …called *dangerous* | 0.18% |
| targeted scams missed | 4.00% |
| Hinglish/Hindi scams missed | 5.71% |
| false alarms on ordinary Hinglish | 0/21 |

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

**Devanagari rows for the corpus.** The tokenizer reads Hindi script now; the
model has no vocabulary for it, because 16 rows out of 3,248 cannot survive
`min_df=3` and a 6,000-feature cap. That is the only thing still in the way,
and it is a data problem rather than a code one. A few hundred Devanagari rows
would put Hindi terms in the vocabulary on their own merits, without touching
vectorizer settings tuned for everything else. They have to be *collected*,
though — writing them to match the benchmark would be grading the corpus
against itself.

**Opt-in network features** — shortener resolution and a URLhaus feed (CC0).
Both break "nothing leaves your computer", so they need one consent surface
designed once, worded the way the Claude tier already is. This is more a
product decision than a technical one.

**Smaller, when convenient**

- Adapter resilience. Gmail and WhatsApp selectors break without notice and
  nothing detects it — auto-scan just goes quiet.
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
