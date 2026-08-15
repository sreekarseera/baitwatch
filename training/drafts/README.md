# Devanagari corpus draft

A reviewable draft, not yet integrated. `training/curated.csv` is unmodified,
the model is not retrained, and parity has not been re-run. This redoes a
prior attempt whose output only lived in an ephemeral scratch directory and
was lost before it could be committed; see `docs/PROGRESS.md`'s `## 2026-08-09`
and `## Next` entries for that history.

## What's here

`devanagari-draft.csv` — 250 rows, columns `text,english_translation,label,category,flag`.

- `text` — Devanagari-script message (a few rows mix in Latin-script brand
  names, acronyms like OTP/UPI/KYC/CVV, and amounts, matching how these
  actually get typed in Hindi SMS/WhatsApp).
- `english_translation` — a faithful translation done alongside each row, not
  a cleaned-up paraphrase. Where the Hindi reads slightly awkwardly (which
  real scam SMS often does), the translation preserves that rather than
  fixing it.
- `label` — `1` scam, `0` legitimate.
- `category` — see breakdown below. Not present in `curated.csv` /
  `curated-hinglish.csv` today; introduced here for review purposes only.
  Nothing downstream reads it — `build_corpus.py` only consumes `text` and
  `label`, so adding this column to `curated.csv` later (if this draft is
  merged) needs no code change, but the column would need to be dropped or
  the ingestion updated, since `train_model.py` expects exactly `text,label`.
- `flag` — empty unless a row is worth a second look. 3 of 250 rows are
  flagged (1.2%); see below.

## Why authored rather than collected

No bulk public corpus of raw Hindi-script scam text turned up (RBI, CERT-In,
and NPCI publish advisories describing scam *mechanisms*, not corpora of
verbatim scam messages; the same gap the 2026-08-09 attempt hit). These rows
are therefore authored to match patterns documented in reporting and
advisories, not scraped or collected. That is a real gap against a
"collected, not written to the benchmark" standard — flagged here rather than
hidden.

### Sources consulted (pattern research, not text scraping)

- Digital arrest: CBI/RBI/police impersonation mechanics, sustained
  video-call coercion, "you cannot disconnect" — [The420.in BHEL employee
  case](https://the420.in/15-lakh-digital-arrest-scam-bhel-employee-cbi-rbi-fake-calls-cyberabad-2026/),
  [Supreme Court directions on digital arrest / mule accounts](https://openthemagazine.com/india/supreme-court-cracks-down-on-digital-arrest-scams-heres-what-the-new-directions-mean),
  [2025 fraud-loss scale, ScamWatchHQ](https://scamwatchhq.com/india-scams-2026-digital-arrest-upi-fraud-epidemic/).
  Confirmed: "digital arrest" has no legal basis in India and the defining
  mechanism is the sustained video call, not a phone call or SMS — used to
  keep this category strictly separate from `courier_customs` and `sim_ekyc`
  below, correcting the prior draft's mislabeling.
- UPI collect-request and KYC-expiry mechanics — [ScanTotal KYC scam
  wording](https://scantotal.net/blog/kyc-update-scam-india/), [ScanTotal UPI
  scams](https://scantotal.net/blog/upi-scams-india/). Confirmed the
  collect-request-as-refund/cashback trick and that "KYC will expire" is
  reported as the most common current SMS lure.
- TRAI/SIM-disconnect robocalls — [PIB press release on fraudulent TRAI
  impersonation](https://www.pib.gov.in/PressReleaseIframePage.aspx?PRID=2047369&reg=3&lang=2),
  [TRAI advisory coverage, News on Air](https://www.newsonair.gov.in/trai-issues-advisory-on-cyber-frauds-financial-scams-misusing-its-name-authority).
  Confirmed the actual reported script ("your number will be deactivated
  within 2 hours") and that TRAI does not itself call or SMS about SIM
  closure — used to keep `sim_ekyc` (IVR-style, no video) distinct from
  `digital_arrest`.
- Sextortion via WhatsApp video call — [IBTimes India blackmail
  reporting](https://www.ibtimes.co.in/nude-video-call-trick-extort-money-fraudsters-blackmail-whatsapp-users-india-836500),
  [Delhi Cyber Police complaint volume, Tribune](https://www.tribuneindia.com/news/delhi/late-night-call-sparks-sextortion-police-arrest-bcom-graduate/amp).
  Confirmed the mechanism (screen-recorded video call, threat to share with
  contacts) and that morphed/edited-photo blackmail of a third party (a
  parent, over a child's photo) is a documented variant, not an invented one.
- Government-scheme lures (PM-Kisan, fake APKs) — [India TV on PM-Kisan
  fraud](https://www.indiatvnews.com/business/personal-finance/pm-kisan-yojana-fraud-prevention-safety-tips-otp-scam-government-scheme-2025-01-17-971759),
  [fake PM-Kisan APK warnings](https://aseemjuneja.in/pm-kisan-whatsapp-scam/).
  Confirmed the SMS-plus-fake-APK combination is a real reported pattern, not
  a synthetic mashup — flagged anyway (see below) since it combines two
  mechanisms in one row.
- Job advance-fee, loan advance-fee, tech-support remote access, debit-alert
  vishing, reward-points, e-commerce refund phishing, courier/customs fee,
  investment/Telegram tip groups, payroll BEC, and traffic-challan patterns
  follow the same shapes already present and cited in `training/curated.csv`
  (rows 210–281, e.g. the India Post customs row, the AnyDesk/TeamViewer
  tech-support rows, the traffic-challan row) and `training/curated-hinglish.csv`,
  extended with more amount/bank/app variety rather than invented from
  nothing.

## Category breakdown (250 rows)

19 scam categories x 8 rows = 152 scam rows; 5 legitimate categories = 98
rows. Scam/legitimate split is 61%/39% — closer to `curated-hinglish.csv`'s
62%/38% than `curated.csv`'s roughly 50%/50%, noted here since the task asked
for "roughly matching curated.csv's ratio" and this leans more scam-heavy.

| category | label | rows |
|---|---|---|
| family_emergency | 1 | 8 |
| courier_customs | 1 | 8 |
| job_advance_fee | 1 | 8 |
| refund_callback | 1 | 8 |
| lottery_windfall | 1 | 8 |
| kyc_block | 1 | 8 |
| digital_arrest | 1 | 8 |
| upi_collect_request | 1 | 8 |
| loan_advance | 1 | 8 |
| ecommerce_refund_phishing | 1 | 8 |
| govt_scheme_lure | 1 | 8 |
| tech_support_remote | 1 | 8 |
| debit_alert_vishing | 1 | 8 |
| reward_points | 1 | 8 |
| sextortion | 1 | 8 |
| sim_ekyc | 1 | 8 |
| investment | 1 | 8 |
| payroll_bec | 1 | 8 |
| traffic_challan | 1 | 8 |
| banking_notification | 0 | 25 |
| personal_family_chat | 0 | 30 |
| work_reminder | 0 | 20 |
| delivery_notification | 0 | 13 |
| otp_legit | 0 | 10 |

## The four problems from the lost first draft, and how this one avoids them

1. **Duplicated-word template bug** (e.g. "पंजाब नेशनल बैंक बैंक:"). Every
   row here is a full hand-written sentence, not a template with a
   substituted noun, so there is no substitution seam for a word to double
   up on. Spot-checked all 8 `kyc_block` rows (the category that hit this
   before) individually: no bank name appears twice.
2. **Template over-reuse** (12 of 20 `kyc_block` rows were two boilerplate
   sentences with the bank swapped). Each of the 8 rows per category here
   uses a different sentence structure, register (SMS notice vs. phone-call
   transcript vs. app alert), and named consequence (account freeze, card
   block, services stopped, investment frozen), not just a different proper
   noun in an identical sentence.
3. **`digital_arrest` mislabeling** (customs-parcel and TRAI/SIM calls
   labeled `digital_arrest`). Fixed by definition: `digital_arrest` is used
   only where the row explicitly describes a *sustained video call* with a
   fake police/CBI/ED/narcotics officer and a threat tied to staying on
   camera. Customs/parcel-seizure calls are `courier_customs`; TRAI/SIM
   robocalls are `sim_ekyc`. Neither of those two categories' 8 rows mentions
   a video call.
4. **419-letter genre transplanted into Hindi** ("foreign lawyer inheritance",
   "army officer needs a partner for $10M"). Not present anywhere in this
   draft — no category here is that genre, and none of the 250 rows use it.

## Self-QA: flagged rows (3 of 250)

- `job_advance_fee` row "नमस्ते, HR टीम से बोल रही हूं, आपका इंटरव्यू सिलेक्ट
  हो गया है..." — "aapka interview select ho gaya hai" is grammatically a
  little off (should read closer to "aapka selection ho gaya hai interview
  ke liye"). Kept because real scam SMS frequently reads exactly this way,
  but flagged so a native-speaker reviewer can judge whether it reads as
  authentic-imperfect or as synthetic-generation artifact.
- `govt_scheme_lure` row "आयुष्मान भारत कार्ड फ्री बनवाएं... APK डाउनलोड" —
  combines a benefit lure with an APK-install ask in one message. This
  combination is reported in the wild (see sources above), but it's a denser
  row than the rest of the category and worth confirming it should stay
  filed under `govt_scheme_lure` rather than a separate malware/APK category
  if one gets added later.
- `sextortion` row "आपकी बेटी की फोटो एडिट करके आपत्तिजनक बना दी है..." — a
  variant mechanism: targets a parent over a morphed photo of a family
  member, rather than the recipient's own recorded video/photo. Kept as a
  documented variant (see sources above) rather than dropped, but flagged
  since it's mechanically different enough from the other 7 rows in the
  category that a reviewer may want to confirm the fit.

## Numeric cross-check

Every row's Hindi text and English translation were checked programmatically:
every digit run (amounts, phone-number fragments, percentages, point counts)
in `text` must also appear in `english_translation`, and vice versa. This
caught one real slip before finalizing — a `reward_points` row said "आज रात
12 बजे तक" (by 12 o'clock tonight) and the first translation draft paraphrased
it as "by midnight tonight," silently dropping the digit. Fixed to keep "12"
in the translation. Zero mismatches remain across all 250 rows.

## Not done here (by design, per the task)

- `training/curated.csv` is untouched.
- The model was not retrained; `training/train_model.py` was not run.
- Parity (`tests/test_parity.py`) was not re-run.
- No merge to `main`, no push. This branch (`wip/devanagari-corpus-draft`) is
  the entire deliverable.

## If this gets integrated later

`build_corpus.py`'s `CURATED` loader reads via `csv.DictReader` and only
pulls `r["text"]` and `r["label"]` by name
(`[(r["text"], int(r["label"])) for r in csv.DictReader(f)]`), so it would
tolerate the extra `english_translation`/`category`/`flag` columns without
code changes if this file were merged straight into `curated.csv` as-is.
Whether to keep those columns in the merged file (for future auditability) or
strip down to `text,label` to match the existing curated files is a decision
for whoever does that merge, not made here. Either way: retrain, then re-run
parity before trusting the result — the whole point of this dataset problem
was that the model has never had Hindi vocabulary to learn from before.
