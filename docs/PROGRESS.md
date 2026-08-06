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
| Model | 3,248 rows, 95.9% validation, 94.8% ±1.7% five-fold CV, 6,000 terms, 262 KB |
| Tests | 191 engine checks, model parity, 5 accuracy gates, 15 browser checks |

Measured accuracy, from `node tests/test_benchmark.mjs`:

| | rate |
|---|---|
| legitimate mail flagged | 0.73% |
| …called *dangerous* | 0.18% |
| targeted scams missed | 4.00% |
| Hinglish/Hindi scams missed | 5.71% |
| false alarms on ordinary Hinglish | 0/21 |

## 2026-08-06

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

**The model cannot see Devanagari.** scikit-learn's default token pattern
splits at Unicode Marks, and Devanagari vowel signs are Marks, so `"खाता"`
tokenizes to nothing. Parity passes because Python and JavaScript are wrong
identically. Hindi-script messages currently rest on the rule layer alone.
Fixing it means changing the token pattern on **both** sides in lockstep and
retraining — the parity test is the safety net, and it must stay green.

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
