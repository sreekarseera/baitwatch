# Progress

Where the project stands and what is worth doing next. For how it works, see
the root [`README.md`](../README.md); this file is the running log.

Last updated **2026-09-01**.

## Current state

| | |
|---|---|
| Repo | `github.com/sreekarseera/baitwatch` (public, MIT) |
| Archive | `github.com/sreekarseera/baitwatch-archive` (private, the original 32-commit history) |
| Detection | 24 heuristics + URL analysis + brand impersonation + on-device classifier |
| Model | 3,603 rows, 94.31% validation, 93.81% ±0.88% five-fold CV, 6,000 terms, 263.9 KB |
| Tests | 297 engine checks, model parity (tokens + predictions), 5 accuracy gates, 3 held-out gates, 29 adapter checks, 20 browser checks |

Measured accuracy, from `node tests/test_benchmark.mjs`:

| | rate |
|---|---|
| legitimate mail flagged | 0.55% |
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

Validation accuracy and false-positive rate have both moved more than once
this month — worth reading the dated entries below before assuming a
regression rather than a deliberate, benchmarked tradeoff. In particular,
validation accuracy went *down* on 2026-08-17 (second entry), from 94.94% to
94.31%, and that was the point: the corpus it is measured against had no
modern transactional mail in it at all, so the old number was partly scoring a
blind spot. Read that entry before trying to win the 0.63 points back.

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

**Commit and merge today's work.** Two independent pieces of 2026-08-16's
work are both done, tested, and still sitting as uncommitted working-tree
changes: the network-consent implementation (below) and the accuracy fixes
(crypto_transfer/investment_scam/prize_or_windfall/credential_request regex
bugs, plus the training-data additions that fixed the Bitwarden/Alpaca false
positives). Neither depends on the other; either can go first. The one
open item below (clicking through the two new toggles) blocks merging the
network-consent half specifically, not the accuracy fixes.

**Click through the two new toggles as an actual person, once.** This is the
one piece of 2026-08-16's work that could not be closed from here — not
because it needs an account or a key (that turned out to be false for
URLhaus, and shortener resolution needs neither), but because
`chrome.permissions.request()`'s consent bubble is native browser chrome,
outside anything CDP's `Input` domain can click. Everything downstream of a
granted permission is now verified end to end (real `is.gd` redirect
resolved correctly; the URLhaus fetch → parse → storage pipeline landed
16,930 real entries) — what's left is confirming the grant/revoke prompts
themselves render sensibly and that a real person can act on them. Turn on
`resolveShorteners` and `checkUrlhaus` in a normal (non-automated) Chrome
profile with this extension loaded, accept both prompts, and check the
options page's status lines and the popup footer read correctly afterward.

**Merge the network-consent implementation (2026-08-16) into `main`** once
the item above is done. It's currently uncommitted working-tree changes
only. (The Devanagari corpus work is separate and already on `main` and
pushed — see the 2026-08-15 correction above.)

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
