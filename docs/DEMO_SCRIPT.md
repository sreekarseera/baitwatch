# Demo script (~90 seconds spoken) — V1 hackathon, archived

> **This is a historical document. It does not describe the current code.**
>
> It is the script for the original hackathon demo, and every step below assumes
> **V1**: a FastAPI backend started with `uvicorn`, a single classifier reporting
> a confidence percentage, and the old blocked-address banner. None of that
> exists any more — V2 has no backend at all, and the scores quoted here were
> produced by a model that has since been retrained on a different corpus. Do not
> follow these instructions.
>
> Kept as a record of how the project was presented. For what the extension does
> now, see the root [`README.md`](../README.md).

Every message referenced here is pre-tested — exact texts and verified scores
in `demo-examples.txt`. Copy-paste, don't retype.

## Before going on stage (5 min prior)

1. Backend running: `cd backend && source venv/bin/activate && uvicorn app:app --reload`
2. Sanity check: analyze one message in the popup — see a result, not an error
3. Gmail open in another tab, logged in
4. `demo-examples.txt` open somewhere you can copy from
5. Blocklist state: if `security.alert.desk@gmail.com` is already blocked from
   rehearsal, that's fine — the banner step still works

## The script — what to say and click

**1. The problem** (say)
> "Scam messages are everywhere — fake bank alerts, fake tech support, fake
> family emergencies. BaitWatch catches them before you act on them."

**2. Catch a scam** (do + say)
- Paste the URGENT bank-suspension message → paste sender
  `security.alert.desk@gmail.com` → click **Analyze**
> "Our trained model flags it — 79% confident. And because it's a scam with a
> sender attached, that email just went onto the blocklist automatically."
- Point at the Blocked Emails section.

**3. No false alarm** (do + say)
- Paste the lunch message → **Analyze**
> "A normal message sails through — it's a real classifier, not a keyword filter."

**4. The banner — the wow moment** (do + say)
- Switch to Gmail → Compose → start typing `security.alert.desk@gmail.com`
> "Weeks later you've forgotten that scammer's address. The moment you type it
> anywhere — mid-compose, no page reload — BaitWatch warns you."
- The purple banner appears as you finish typing the address. Pause on it.

**5. It's a real product** (do + say)
- Back to popup → hover a history row (tooltip shows the sender) → click
  **Export History** → open the CSV.
> "Everything's logged and exportable. All state lives in the browser;
> the backend is a stateless classifier."

**6. Close honestly** (say)
> "What's custom: a scikit-learn model we trained and stress-tested ourselves —
> including scam types like tech-support and family-impersonation that avoid
> obvious 'urgent' language. Known limits: the dataset is small, it runs
> locally, and canvas apps like Google Docs can't be scanned live — that's a
> browser-level restriction on every extension. There's also an automated
> 17-check test suite behind this."

## If something breaks live

- **Popup shows the backend error** → the uvicorn terminal died; rerun the
  command from step 1 of prep (venv must be active). 10 seconds.
- **Banner doesn't appear in Gmail** → wrong profile or the address isn't in
  the blocklist; check the popup's Blocked Emails list, re-analyze scam #1
  with the sender filled in.
- **Total backend failure** → demo the extension side only: history,
  blocklist, exports, and the banner (none of them need the backend), and
  narrate the classify step over screenshots.

## Backup second scam (if judges ask for another)

Use the Microsoft tech-support message (63%) or the family-impersonation
message (62%) — both verified. The point to make: neither uses the word
"urgent", and the model still catches them.
