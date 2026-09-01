// Rule-based scam signals.
//
// These exist alongside the statistical model rather than under it. The model
// gives one opaque number; these give the user a reason. They also cover the
// social-engineering patterns that are stable across languages and rewrites —
// a gift-card request is a gift-card request however it's phrased — where a
// bag-of-words model trained on a few hundred examples is brittle.

import { normalize } from "../lib/text.js";

// ---------------------------------------------------------------------------
// Hinglish and Devanagari vocabulary.
//
// The tactics these rules encode — UPI collect-requests, KYC expiry, digital
// arrest — are largely Indian, but every pattern above matches English wording
// only, so the same scam in Hinglish tripped nothing at all. Measured before
// this block existed: 64% of Hinglish scams missed, and 100% of Devanagari
// ones, against 3.6% for English.
//
// Both scripts can be covered here because heuristics run regexes over
// normalize()'d text and never tokenize, which is what let this layer cover
// Devanagari back when the tokenizer could not. The tokenizer reads it now
// (see INDIC_MARKS in lib/text.js), and as of the 2026-08-17 corpus the model
// has a toehold in Devanagari at last: 65 of its 6,000 terms carry Hindi
// script, where previously none did. Do not read that as coverage. They are
// overwhelmingly function words — आपका, इस, और, कर — because those are what
// clear min_df=3 first; almost no discriminative scam vocabulary is among them.
// So these rules still carry effectively all of the Hindi-script detection, and
// a Hindi tactic nobody has written a rule for has no model underneath it to
// catch what they miss, the way there is in English.
//
// Transliteration has no agreed spelling — "bhejiye", "bhejo", "bhej do" are
// one word — so stems are used where the stem is distinctive enough to be safe
// on its own. "bhej" is; "kar" (do) would not be, and is never used alone.
// ---------------------------------------------------------------------------
const HI = {
  // send / give / tell — the transmission verbs. "जमा" (deposit/submit) is
  // how a fee gets sent, not a way of sending it, but the two read the same
  // to whoever pays, so it belongs with the other transmission verbs.
  // "ट्रांसफर" (transfer) is the English loanword spelled in Devanagari, not
  // a translation of it — real UPI/bank-transfer messages say "ट्रांसफर करो"
  // far more often than "भेजो", the same loanword pattern already covered for
  // "जॉब", "रिफंड", "चार्ज" elsewhere. Missing it meant a Devanagari message
  // stating an amount and "ट्रांसफर करो" carried no send-verb signal at all.
  // (Plain English "transfer" is deliberately not added here — it is already
  // matched explicitly, proximity-gated to a money word, in the wantsMoney
  // checks below; adding it to this bare union would let it fire unguarded
  // through the money-optional third branch too.)
  // "शेयर कर" (share) is the single most common way a Devanagari message asks
  // for an OTP — "OTP शेयर करें" — and none of the transmission verbs above
  // covered it, so that phrasing carried no signal at all. Gated on the verb
  // "कर" rather than bare "शेयर", which also means "share" as in stock market
  // ("शेयर बाजार") and would fire on ordinary investment writing. The negated
  // form is still handled: CREDENTIAL_ADVICE_RE already strips "शेयर न करें".
  send: "bhej\\w*|भेज\\w*|de\\s*do|दे\\s*दो|jama\\w*|जमा|ट्रांसफ़?र\\w*|शेयर\\s*कर\\w*|साझा\\s*कर\\w*",
  tell: "bata(?:o|iye|ye|yein|na)|बता(?:ओ|इए|एं|ना)",
  enter: "daal(?:o|iye|ein|na)?|dal(?:o|iye|ein)|डाल(?:ो|िए|ें|ना)?",
  money: "pais[ae]|rupay[ae]?|rupees|rakam|राशि|पैस[ेा]|रुपय[ेा]|रकम",
  account: "khat[ae]|खात[ेा]|account|खाता|कार्ड|card",
  // Split in two because every call site below needs \b around the Latin
  // half only. JS's \b is an ASCII word-boundary — it is defined as a
  // transition between \w ([A-Za-z0-9_]) and non-\w, and Devanagari
  // characters are never \w, so `\b(?:तुरंत)\b` can never match: neither
  // side of "तुरंत" is ever a \w character for \b to transition against.
  // A single combined string wrapped in one \b, as this used to be, silently
  // dropped every Devanagari alternative while looking like it covered both
  // scripts. Verified empirically: /\b(?:अभी)\b/.test("अभी अस्पताल") is
  // false; /अभी/.test(...) is true.
  // "abhi"/"अभी" deliberately excluded from the Devanagari side: in English
  // Hinglish it mostly appears as an imperative ("abhi bhejo"), but in
  // Devanagari "अभी" just as often means "just now" describing something
  // that already happened — "अभी 2,500 रुपये ट्रांसफर किए" is a bank
  // reporting a completed transfer, not a demand. Keeping it flagged every
  // legitimate "just now" notification as urgent.
  urgentLatin: "turant|abhi|jald(?:i|ee)|foran",
  urgentDevanagari: "तुरंत|जल्दी|फ़?ौरन",
  // "सस्पेंड" is the Devanagari-spelled loanword for "suspend" — real bank
  // SMS use it at least as often as "ब्लॉक", and only the Latin spelling
  // was covered.
  blocked:
    "band\\s*ho|block\\s*ho|suspend|सस्पेंड|nilambit|बंद\\s*हो|ब्लॉक|निलंबित|समाप्त|" +
    "रोक(?:ा|ी|दिया)?|काम\\s*नहीं\\s*करेगा",
  // ड्यूटी (duty) is how a customs/import charge is actually named in
  // Devanagari SMS — "शुल्क" is formal-register Hindi that real scam
  // messages use rarely.
  fee: "shulk|शुल्क|फ़?ीस|charge|fee|duty|ड्यूटी|चार्ज|क्लियरेंस",
  // वारंट(?!ी) excludes "वारंटी" (warranty) — वारंट (warrant) is its own
  // word but also happens to be the first five characters of the routine
  // e-commerce word for "warranty", and a bare substring match can't tell
  // them apart. Same class of bug as कस्टम(?!र) above, on a different word.
  // "पुलिस सत्यापन" / "police verification" is a routine step in getting a
  // passport, a rental agreement or a job — the single most common way the
  // word "police" appears in legitimate Indian mail, and it made a passport
  // approval notice fire both threat_of_consequence and impersonated_authority.
  // Excluded by what follows the word rather than by dropping the word, the
  // same shape as वारंट(?!ी) and कस्टम(?!र) below.
  police:
    "cyber\\s*cell|साइबर\\s*सेल|cbi|सीबीआई|police(?!\\s*(?:verification|clearance))|पुलिस(?!\\s*(?:सत्यापन|वेरिफिकेशन|क्लीयरेंस))|warrant|वारंट(?!ी)|giraftar|गिरफ़?्तार|थाना|थाने|" +
    "\\bed\\b|ईडी|फेमा|supreme\\s*court|सुप्रीम\\s*कोर्ट|money\\s*laundering|मनी\\s*लॉन्ड्रिंग|दूरसंचार",
  // "badhai"/"बधाई" is congratulation, not windfall — see CONGRATS_RE, which
  // holds it (and its English twin) behind a nearby-winnings gate. The terms
  // left here each name the winnings themselves.
  prize: "lotter[iy]|लॉटरी|jeet\\s*ga(?:ye|ya)|जीत\\s*ग(?:ए|या)|inaam|इनाम",
  kyc: "kyc|केवाईसी",
  // Parcel/courier vocabulary, Devanagari and Devanagari-spelled loanwords —
  // delivery_redispatch_fee had no Hindi-script coverage at all before this.
  // कस्टम(?!र) excludes "कस्टमर" (customer) — कस्टम (customs) is its own
  // word but also happens to be the first four characters of the routine
  // word for "customer", and a bare substring match can't tell them apart.
  parcel: "parcel|package|courier|consignment|पार्सल|पैकेट|कूरियर|कोरियर|कस्टम(?!र)|कंसाइनमेंट",
};

const CREDENTIAL_NOUN_RE =
  /\b(?:password|passcode|pin(?:\s*(?:number|code))?|otp|one[\s-]?time\s*(?:password|code|pin)|cvv|card\s*(?:number|details)|security\s*code|(?:confirmation|verification)\s*code|seed\s*phrase|recovery\s*phrase|private\s*key|aadhaar|ssn|social\s*security)\b|ओटीपी|पिन|आधार|पासवर्ड/;

// The secret leaving your possession, *towards whoever is asking*. The
// direction is the whole signal: "send OTP to your registered mobile" is a real
// bank's own button and "send me your OTP" is a theft, and both contain "send".
// So the verb has to carry an indirect object pointing back at the sender. Bare
// verbs matched far too much — including the word "email" sitting on the login
// form of every site in the world.
const CREDENTIAL_TRANSMIT_RE = new RegExp(
  "\\b(?:(?:send|forward|give|tell|text|whatsapp|email|message)\\s+(?:it\\s+)?(?:me|us|back|to\\s+(?:me|us))" +
    "|shar(?:e|ing)\\s+(?:your|the|it|with)|reply\\s+(?:with|back\\s+with)|revert\\s+with|provide\\s+(?:me|us))\\b" +
    // Hinglish has no indirect-object cue to lean on the way English does:
    // "OTP bhejiye" is already the entire request, with no "me" in it. The
    // imperative form carries the direction on its own.
    `|${HI.send}|${HI.tell}`
);

// Verbs that describe typing a secret into a form. Damning in a message,
// unremarkable on the login page it describes — see the rule below.
//
// The determiner is required, not decoration. Bare verbs matched anywhere in
// the message, so "Your Aadhaar update request has been processed" — a
// completion notice with nothing to do — read as a credential request off the
// noun "update" sitting next to "Aadhaar". A real instruction points the verb
// at something of yours ("enter your password", "update your details"); a noun
// phrase like "update request" does not.
const CREDENTIAL_ENTRY_RE = new RegExp(
  `\\b(?:enter|provide|confirm|verify|submit|update)\\s+(?:your|the|this|it|below|these)\\b|${HI.enter}`
);

// The advice *against* handing a secret over, which is how every real OTP
// message ends. "Never share your OTP", "किसी को न बताएं", "kisi ko na bataye"
// all put a transmission verb next to a credential noun — the exact shape
// CREDENTIAL_TRANSMIT_RE looks for — so the single most reliable marker that a
// message is a genuine bank notification was being read as the theft it warns
// against. Measured: all five held-out bank OTP messages flagged, three of them
// "dangerous", entirely on this.
//
// Only the negation separates the two, so only the negation is tested here.
// "Please share your OTP to verify your account" is untouched and still fires.
// Latin and Devanagari alternatives are kept apart because JS's \b is an ASCII
// word boundary and can never match against a Devanagari character — see the
// note on HI.urgentLatin above.
const CREDENTIAL_ADVICE_RE = new RegExp(
  "\\b(?:never|not|no\\s*one|nobody|avoid)\\b[^.!?]{0,25}" +
    "\\b(?:shar(?:e|ing)|disclos(?:e|ing)|reveal(?:ing)?|tell|give|send|forward|provide)\\b" +
    "|\\b(?:na|nahi|mat|kabhi)\\s+(?:bata\\w*|bhej\\w*|share\\s*kar\\w*)" +
    "|(?:न|नहीं|मत)\\s*(?:बता|भेज|शेयर|साझा|दे)"
);

// Same-sentence gate, not "anywhere in the message" — a real crypto
// brokerage's routine account email says "crypto" (their own product line,
// often right in a legal-entity name like "Alpaca Crypto LLC") and,
// completely separately, "invest" or "deposit" in unrelated boilerplate
// ("please consider your investment objectives before you invest or deposit
// funds"). An old unanchored AND fired on that with no ask anywhere in the
// message. A scam always puts the currency and the ask in the same breath —
// "send BTC", "double your Bitcoin" — so requiring them within one sentence
// keeps the real cases (see the "crypto doubling" fixture in
// tests/test_engine.mjs) and drops this one. Precompiled at module scope,
// like every other rule's pattern, rather than rebuilt on every message.
const CRYPTO_RE = String.raw`(?:bitcoin|btc|ethereum|eth|usdt|crypto(?:currency)?|wallet\s*address)`;
const CRYPTO_VERB_RE = String.raw`(?:send|transfer|deposit|invest|double|pay|scan)`;
const CRYPTO_TRANSFER_RE = new RegExp(
  `\\b${CRYPTO_RE}\\b[^.!?]{0,40}\\b${CRYPTO_VERB_RE}\\b|\\b${CRYPTO_VERB_RE}\\b[^.!?]{0,40}\\b${CRYPTO_RE}\\b`
);

// Congratulation is a greeting, not a lure. Bare "congratulations" convicted at
// weight 1.9 on every ordinary well-wish — measured on a real LinkedIn feed
// post ("Congratulations to <name> on securing admission to <university>"),
// which scored 51/100 and warned the user. Every scam row in curated.csv that
// opens this way also says "you've won", which the rule's first branch already
// matches, so the bare word was carrying no case of its own.
//
// The gate is a plain character window, not the same-sentence gate the other
// rules use: the greeting is nearly always its own sentence ("Congratulations!
// Your refund of Rs 4,500 is ready"), so a [^.!?] window could never reach the
// winnings it is meant to be gated on.
//
// "won"/"winner"/"selected" are deliberately absent from the gate. They read as
// windfall next to "congratulations" but are exactly how a legitimate message
// congratulates someone on an award or a job — and the scam phrasings ("you
// have won", "you have been selected") are already their own branch. Only nouns
// that name unearned money or goods are gate terms.
const CONGRATS_RE = /\bcongratulations\b|\bbadhai\b|बधाई/;
const WINNINGS_RE =
  /\b(?:prize|reward|lottery|jackpot|refund|cashback|bonus|voucher|gift\s*card|winnings|unclaimed|lucky\s*draw|claim\s*(?:your|now|it)|crore|lakh|rs|inr)\b|इनाम|लॉटरी|रिफंड|कैशबैक|बोनस|पुरस्कार|लाख|करोड़|रुपये|क्लेम/;
const CONGRATS_WINDFALL_RE = new RegExp(
  `(?:${CONGRATS_RE.source})[\\s\\S]{0,60}(?:${WINNINGS_RE.source})` +
    `|(?:${WINNINGS_RE.source})[\\s\\S]{0,60}(?:${CONGRATS_RE.source})`
);

// A gift card named anywhere used to be the whole rule, at the heaviest weight
// any rule carries (3.0) — enough to convict on its own. But the tactic this
// rule names is being asked to *pay* in gift cards, and an ordinary retail
// newsletter offering one as a prize ("answer correctly for a chance to win a
// gift card") satisfied the noun without any ask at all. Same same-sentence
// gating pattern crypto_transfer and prize_or_windfall already use, for the
// same reason.
//
// The "you've won a $500 gift card, click to claim" scams in curated.csv are
// unaffected in verdict: they are what prize_or_windfall and artificial_urgency
// are for, and they still land well above the dangerous threshold without this
// rule needing to fire on the noun alone.
const GIFT_CARD_RE =
  /\b(?:gift\s*card|itunes\s*card|steam\s*(?:card|wallet)|google\s*play\s*card|voucher\s*code|prepaid\s*card)\b|गिफ्ट\s*कार्ड|आइट्यून्स|स्टीम\s*कार्ड|वाउचर/;
const GIFT_CARD_ASK_RE =
  /\b(?:buy|purchase|get|pick\s*up|load|top\s*up|pay|paying|payment|send|forward|share|scratch|redeem)\b|खरीद|भेज|पेमेंट|पैसे/;
const GIFT_CARD_PAYMENT_RE = new RegExp(
  `${GIFT_CARD_ASK_RE.source}[^.!?]{0,60}(?:${GIFT_CARD_RE.source})` +
    `|(?:${GIFT_CARD_RE.source})[^.!?]{0,60}${GIFT_CARD_ASK_RE.source}`
);

/**
 * Each rule is {id, weight, why, test}. `why` is written to be shown to a
 * non-technical user verbatim, so it explains the *risk*, not the regex.
 *
 * `test` receives the normalized text and a context object describing where the
 * text came from — currently just whether the page carries a real credential
 * field. Only `credential_request` reads it; the rest ignore the argument.
 */
const RULES = [
  {
    id: "credential_request",
    weight: 2.2,
    why: "It asks for a password, PIN, OTP, or card number. No real bank, retailer, or IT team ever asks for these.",
    test: (t, ctx) => {
      if (!CREDENTIAL_NOUN_RE.test(t)) return false;
      // Cut the "never share this with anyone" advice out before looking for a
      // request, rather than skipping the message wholesale when advice is
      // present. A scammer who pastes a real bank footer under their own ask
      // still gets caught on the ask; the footer alone convicts nobody.
      const asked = t.replace(new RegExp(CREDENTIAL_ADVICE_RE, "g"), " ");
      // On a page that has a real login form, "enter your password" is what
      // every legitimate sign-in page in the world says. Judged as a message
      // it reads as a credential request, which made the rule fire on the
      // genuine bank and workplace logins the whole-page scan exists to check.
      // There, only asking you to *transmit* the secret counts.
      return ctx.hasCredentialForm
        ? CREDENTIAL_TRANSMIT_RE.test(asked)
        : CREDENTIAL_TRANSMIT_RE.test(asked) || CREDENTIAL_ENTRY_RE.test(asked);
    },
  },
  {
    id: "gift_card_payment",
    weight: 3.0,
    why: "It asks for payment in gift cards. Gift cards are untraceable and are the single most common scam payment method — no legitimate business, agency, or manager collects payment this way.",
    test: (t) => GIFT_CARD_RE.test(t) && GIFT_CARD_PAYMENT_RE.test(t),
  },
  {
    id: "crypto_transfer",
    weight: 2.4,
    why: "It asks you to send cryptocurrency. Crypto payments cannot be reversed or recovered once sent.",
    test: (t) => CRYPTO_TRANSFER_RE.test(t),
  },
  {
    id: "upi_collect_request",
    weight: 2.6,
    why: "It asks you to approve a UPI request or scan a QR code to *receive* money. Approving a UPI request or scanning a QR code always sends money out of your account — it never brings money in.",
    test: (t) =>
      (new RegExp(`\\b(?:upi|gpay|google\\s*pay|phonepe|paytm|bhim|qr\\s*code)\\b|यूपीआई|क्यूआर|कलेक्ट\\s*रिक्वेस्ट`).test(t) &&
      new RegExp(
        `\\b(?:collect\\s*request|accept|approve|scan|enter\\s*(?:your\\s*)?pin|receive|refund|cashback)\\b` +
        `|${HI.enter}|स्वीकार|स्कैन|एक्सेप्ट`
      ).test(t)) ||
      // The classic OLX/marketplace version names no UPI app at all — "I'm
      // sending the payment, just accept the request on your screen" — so the
      // brand-name gate above could never reach it. Requires the *imperative*
      // accept ("एक्सेप्ट कर दीजिए"), which is what keeps a routine "आपकी
      // रिक्वेस्ट स्वीकार कर ली गई है" ("your request has been accepted", a
      // completed passive) from firing on the same two words.
      (/(?:रिक्वेस्ट|request)[^।.!?]{0,40}(?:एक्सेप्ट|स्वीकार|accept)\s*कर\s*(?:दीजिए|दीजिये|दो|दें|ें|िए)/.test(t) &&
        // Money has to be in the message, or this is a meeting invite. "मीटिंग
        // रिक्वेस्ट एक्सेप्ट कर दीजिए" is the same imperative in the same
        // words, and scored 35 on the first version of this branch. The tactic
        // is always about a payment supposedly arriving, so requiring the money
        // word is what separates the two rather than any grammatical cue.
        new RegExp(`${HI.money}|पेमेंट|payment|भुगतान|अमाउंट`).test(t)),
  },
  {
    id: "account_suspension",
    weight: 1.5,
    why: "It claims your account is suspended, locked, or about to be closed. Manufactured account trouble is the standard hook for stealing logins.",
    test: (t) =>
      // "net banking"/"netbanking" is how Indian bank customers actually name
      // their online-banking access — a real noun in its own right, not just
      // a modifier on "account" — and was missing from the noun list, so
      // "your net banking suspended" carried no signal at all.
      // "sim" is a noun in its own right here — a SIM-deactivation threat is the
      // most common Indian version of this tactic.
      //
      // block(?:ed)?(?!...attempt) because a bank reporting that it "already
      // blocked the attempt" is describing a defence, not a suspended account,
      // and the rule read the blocked *attack* as a blocked *account*. Same
      // shape of fix as वारंट(?!ी) and कस्टम(?!र).
      //
      // "interruption" was tried here and removed: "to avoid interruption" is
      // what a real dunning email says when your card expires (Adobe's, in the
      // held-out set, scored 64 on it) *and* what the Netflix-lookalike phish in
      // test_engine.mjs says. The text does not separate them — the URL does,
      // which is brand_claim_mismatch's job, not this rule's.
      /\b(?:account|card|profile|subscription|service|net\s*banking|sim)\b[^.!?]{0,40}\b(?:suspend(?:ed)?|lock(?:ed)?|block(?:ed)?(?!\s*(?:the\s*)?(?:attempt|attack|transaction|charge|payment|it\b))|disabl(?:ed)?|deactivat(?:ed)?|restrict(?:ed)?|clos(?:ed|ure)|terminat(?:ed)?|on\s*hold)\b/.test(t) ||
      // "We detected unusual activity in your account. Login to confirm." is
      // the oldest pretext phish there is and tripped nothing at all. Both
      // halves are required, and deliberately not sentence-gated: the pretext
      // and the instruction are almost always separate sentences. The action
      // half is what keeps a real bank's own alert quiet — those report the
      // activity and tell you to call if it wasn't you, they do not send you to
      // a login.
      (/\b(?:unusual|suspicious|unauthori[sz]ed|unrecogni[sz]ed|abnormal)\s*(?:activity|log\s*in|login|sign[\s-]?in|access|transaction)\b/.test(t) &&
        /\b(?:log\s*in|login|sign\s*in|verify|confirm|click|update\s*your|re-?activate)\b/.test(t)) ||
      // "aapka khata band ho jayega", "KYC expire ho gaya hai"
      new RegExp(`(?:${HI.account}|${HI.kyc}|नेटबैंकिंग)[^.!?]{0,40}(?:${HI.blocked}|expire|khatam|खत्म)`).test(t) ||
      new RegExp(`(?:${HI.kyc})[^.!?]{0,25}(?:expire|समाप्त|pending|update)`).test(t) ||
      // A telecom cut-off is account suspension wearing different nouns — the
      // threat is "सेवाएं बंद होंगी" (services will stop), and the account word
      // that HI.account looks for sits too far away to reach it.
      // Conditional on *your* inaction, which is what makes it a threat rather
      // than an announcement: "प्रोसेस पूरी न होने पर सेवाएं बंद होंगी". A
      // maintenance notice ("रखरखाव के कारण सेवाएं बंद रहेंगी") states the same
      // outcome with nothing for the reader to do, and fired on the first
      // version of this branch.
      /(?:सिम|सेवाएं|सेवाओं|सेवा|कनेक्शन)[^।.!?]{0,45}(?:बंद|ब्लॉक|निलंबित|समाप्त)/.test(t) &&
        /न\s*होने|नहीं\s*तो|वरना|अन्यथा|पूरी\s*न|विफल|फेल|तुरंत|जल्दी/.test(t),
  },
  {
    id: "artificial_urgency",
    weight: 1.2,
    why: "It sets a countdown. Deadlines like this exist to stop you checking with someone before you act.",
    test: (t) => {
      // A short-lived link, code or session is a security control, not a
      // countdown — every password-reset and email-verification message ever
      // sent says one expires, and saying so protects the reader rather than
      // rushing them. The pressure this rule is named for is an *account* or an
      // *offer* expiring, which is the scam's manufactured stake. Dropping the
      // clause rather than the message keeps "your account expires in 24 hours,
      // this link expires soon" firing on the half that matters.
      const t2 = t
        .replace(
          // "password" deliberately not in this list, though it was at first.
          // A *link*, code, token or session expiring is a security control the
          // sender built; a *password* expiring is one of the oldest phishing
          // pretexts there is ("Your iCloud password will expire today. Reset
          // it now: <not-apple.example>"), and stripping it took that row's
          // only urgency signal away.
          /\b(?:link|url|code|otp|token|session|invit(?:e|ation)|verification)\b[^.!?]{0,20}\bexpir\w*[^.!?]{0,25}/g,
          " "
        )
        // The same clause in Devanagari — "वेरिफिकेशन कोड ... जल्दी एक्सपायर हो
        // जाएगा" — which the English pattern above cannot reach. Note the "।"
        // (danda) in the exclusion class alongside ".!?": it is the Devanagari
        // full stop, and leaving it out would let the strip run past the end of
        // a sentence. An *account* expiring is deliberately still not stripped,
        // matching the English half: only a code, link or session qualifies.
        .replace(/(?:कोड|ओटीपी|लिंक|पासवर्ड|टोकन|सेशन|वेरिफिकेशन)[^।.!?]{0,40}एक्सपायर[^।.!?]{0,20}/g, " ")
        // "Report suspicious calls immediately" is the anti-fraud notice every
        // bank puts on its own login page, and it read as the pressure it warns
        // about. A scammer does not urge you to report them, so the urgency in
        // a report-this instruction always belongs to the defender.
        .replace(/\breport\s+(?:any\s+|all\s+)?(?:suspicious|fraudulent|fraud|phishing|unauthori[sz]ed|this|it)\b[^.!?]{0,40}/g, " ");
      return (
        /\b(?:within\s*\d+\s*(?:hour|hr|minute|min|day)|in\s*the\s*next\s*\d+\s*(?:hour|minute)|before\s*(?:midnight|today|tonight|it\s*expires)|expir(?:es|ing|e)\s*(?:today|soon|in)|last\s*(?:chance|warning)|final\s*(?:notice|warning|reminder)|immediately|right\s*away|act\s*now|urgent(?:ly)?|asap)\b/.test(t2) ||
        new RegExp(`\\b(?:${HI.urgentLatin})\\b|${HI.urgentDevanagari}|आज\\s*रात|aaj\\s*raat`).test(t2)
      );
    },
  },
  {
    id: "threat_of_consequence",
    weight: 1.7,
    why: "It threatens arrest, legal action, or a fine. Real agencies send written notices; they do not threaten you over email or chat.",
    test: (t) =>
      // police(?!\s*(?:verification|clearance)) for the same reason as HI.police
      // above — a passport's police verification step is not a threat.
      /\b(?:arrest(?:ed)?|legal\s*action|lawsuit|court|police(?!\s*(?:verification|clearance))|fir\b|warrant|prosecut(?:e|ion)|penalt(?:y|ies)|fine|challan|seiz(?:e|ed|ure)|deport|jail|criminal\s*(?:case|charge))\b/.test(t) ||
      new RegExp(`${HI.police}|मामला\\s*दर्ज|case\\s*darj|थाना|थाने|चालान|जमानत`).test(t),
  },
  {
    id: "prize_or_windfall",
    weight: 1.9,
    why: "It says you've won something you never entered, or money is waiting for you. Unsolicited winnings are a lure to collect your details or an upfront \"fee\".",
    test: (t) =>
      // The subject isn't always literally "you" — "your email/number/name
      // was selected" is the same lure with the pronoun swapped out, and the
      // old pattern required "you" right before "selected/chosen" to match.
      /\b(?:you(?:'ve| have)?\s*(?:been\s*)?(?:won|win|selected|chosen)|(?:was|has\s*been|have\s*been)\s*(?:selected|chosen)\s*to\s*receive|lucky\s*(?:winner|draw)|claim\s*your\s*(?:prize|reward|gift)|lottery|jackpot|unclaimed\s*(?:funds|money|refund)|inherit(?:ance|ed))\b/.test(t) ||
      new RegExp(HI.prize).test(t) ||
      CONGRATS_WINDFALL_RE.test(t) ||
      // Devanagari-spelled loanwords for the same "unexpected money is
      // waiting" lure — refunds, reward points, cashback, and bonuses that
      // were never earned, not the classic lottery framing. Gated on a
      // nearby call to action: a bank routinely says "cashback credited,
      // refund will arrive in 5 days" with nothing for the reader to do,
      // and that has to read as the routine notice it is. The scam version
      // always asks for a click, a claim, or a form.
      // "वापस पाने" (to get it back) is how a refund lure is phrased when the
      // word रिफंड never appears, and क्लिक/लॉगिन belong beside the other
      // calls to action: a real refund notice tells you money is coming, it
      // does not route you through a login page to collect it.
      new RegExp(`(?:रिफंड|रिवॉर्ड|बोनस|कैशबैक|पॉइंट्स|वापस\\s*पान[ेा])[^.!?]{0,45}(?:क्लेम|रिडीम|लिंक|apk|डाउनलोड|फॉर्म|वेरिफ|एक्सपायर|पिन|क्लिक|लॉगिन|लॉग\\s*इन)`).test(t),
  },
  {
    id: "advance_fee",
    weight: 2.0,
    why: "It asks for a payment up front to release a larger sum. That larger sum does not exist.",
    test: (t) =>
      /\b(?:processing\s*fee|clearance\s*fee|customs\s*(?:fee|duty|charge)|release\s*fee|registration\s*fee|handling\s*charge|small\s*(?:fee|amount)|refundable\s*deposit)\b/.test(t) ||
      // "processing fee bhejiye", "clearance shulk bharkar", "file charge 999"
      //
      // The named-cost half needs the same "and they want it sent" requirement
      // its sibling has. Bare "delivery fee" convicted at weight 2.0 on its
      // own, and "Delivery fee Rs 30" is a line item on every checkout page and
      // order confirmation that exists — the real Swiggy cart page was called
      // dangerous on nothing else. An advance fee is only a scam when someone
      // is asking you to send it.
      new RegExp(
        `(?:${HI.fee})[^.!?]{0,25}(?:${HI.send}|bhar|भर|pay)` +
          // Either order, like CRYPTO_TRANSFER_RE: "pay the file processing
          // charge" puts the verb first, "delivery fee bhejiye" puts it last.
          `|(?:file|delivery|clearance|क्लियरेंस|processing)\\s*(?:${HI.fee})[^.!?]{0,30}(?:${HI.send}|bhar|भर|pay\\b)` +
          `|(?:${HI.send}|bhar|भर|pay\\b)[^.!?]{0,30}(?:file|delivery|clearance|क्लियरेंस|processing)\\s*(?:${HI.fee})`
      ).test(t) ||
      // Loan-advance-fee scams name the up-front cost without a fee word at
      // all — "GST क्लियरेंस के लिए 750 रुपये", "स्टाम्प ड्यूटी" — the
      // charge is identified by what it's for, next to a rupee amount.
      new RegExp(`(?:लोन|loan)[^.!?]{0,60}(?:क्लियरेंस|स्टाम्प|clearance|stamp)[^.!?]{0,20}(?:${HI.money})`).test(t),
  },
  {
    id: "impersonated_authority",
    weight: 1.4,
    why: "It claims to be from a bank, tax office, or support desk. Check by contacting them yourself using a number you already have — never one from the message.",
    test: (t, ctx) =>
      // On the authority's own domain the claim is true, so there is nothing to
      // impersonate — see onOfficialDomain in engine.js.
      !ctx.onOfficialDomain &&
      (/\b(?:income\s*tax|irs\b|hmrc|customs|cyber\s*cell|trai\b|rbi\b|federal|government|microsoft\s*support|apple\s*support|tech\s*support|security\s*team|fraud\s*department)\b/.test(t) ||
        new RegExp(`${HI.police}|bank\\s*se\\s*bol|बैंक\\s*से\\s*बोल|hr\\s*se\\s*bol|कस्टम(?!र)|इनकम\\s*टैक्स|आयकर`).test(t)),
  },
  {
    id: "secrecy_request",
    weight: 2.1,
    why: "It tells you to keep this quiet or not to contact anyone. Isolating you from a second opinion is a deliberate tactic, not a business practice.",
    test: (t) => {
      // "Do not share this OTP with anyone" is the opposite of this rule: it is
      // the bank telling you to keep a *secret* secret, not a scammer telling
      // you to keep a *transaction* secret. This rule is about isolation from a
      // second opinion — see the wording above — so when the thing not to be
      // shared is a credential, it is security advice and nothing else.
      // Strip only the advice clauses that are actually about a credential.
      // CREDENTIAL_ADVICE_RE is deliberately generic — it matches any negated
      // transmission verb — and "घर वालों को मत बताना" ("don't tell the
      // family") matches it exactly while being the secrecy *demand* this rule
      // exists to catch, not advice against one. The credential noun nearby is
      // what separates "never share your OTP" from "don't tell anyone".
      const withoutAdvice = t.replace(new RegExp(CREDENTIAL_ADVICE_RE, "g"), (match, offset) => {
        const around = t.slice(Math.max(0, offset - 40), offset + match.length + 40);
        return CREDENTIAL_NOUN_RE.test(around) ? " " : match;
      });
      return (
        /\b(?:do\s*not\s*(?:tell|inform|discuss|share\s*this)|keep\s*(?:this|it)\s*(?:confidential|secret|between\s*us)|don'?t\s*(?:tell|call|contact)\s*(?:anyone|police|bank)|without\s*informing)\b/.test(withoutAdvice) ||
        // "kisi ko mat bataiyega", "police ko mat bataana"
        // "घर वालों को मत बताना" (don't tell the family) is the family-emergency
        // scam's own version of this, and only किसी/पुलिस were covered.
        new RegExp(`(?:kisi\\s*ko|police\\s*ko|किसी\\s*को|पुलिस\\s*को|घर\\s*वालों\\s*को|ghar\\s*walon\\s*ko)\\s*(?:mat|nahi|मत|नहीं)`).test(withoutAdvice)
      );
    },
  },
  {
    id: "sextortion_threat",
    weight: 2.3,
    why: "It threatens to share an intimate or embarrassing photo or video unless you pay. Paying does not make the threat stop — it confirms you will pay again.",
    test: (t) =>
      /\b(?:nude|naked|intimate|obscene|explicit|morphed?)\s*(?:video|photo|picture|pic)\b|screen\s*record(?:ed|ing)?/.test(t) ||
      /न्यूड|नग्न|आपत्तिजनक|अश्लील/.test(t) ||
      // A recording/photo mentioned near a threat to make it public — the
      // generic shape covers both "your own video" and "your daughter's
      // morphed photo" variants without needing a separate rule for each.
      (/वीडियो|फोटो|तस्वीर|स्क्रीनशॉट|video|photo|screenshot/.test(t) &&
        /वायरल|लीक|फैला|भेजने\s*से\s*पहले|भेज(?:ना|ूंगा|\s*दूंगा)|viral|leak(?:ed)?/.test(t)),
  },
  {
    id: "unexpected_attachment_or_install",
    weight: 1.6,
    why: "It wants you to install software or open an attachment to fix a problem. That software is how they take control of your device.",
    test: (t) =>
      /\b(?:anydesk|teamviewer|quick\s*support|remote\s*(?:access|desktop)|install\s*(?:this|the)\s*app|download\s*(?:the\s*)?(?:apk|attachment|file)|enable\s*(?:macros|installation\s*from\s*unknown))\b/.test(t) ||
      // "डाउनलोड करके" (having downloaded) is as common an imperative form as
      // "करें"/"कीजिए" and was not covered, and `apk\s*डाउनलोड` required the
      // two to be adjacent — real messages say "इस APK को डाउनलोड करके".
      /रिमोट\s*एक्सेस|स्क्रीन\s*शेयर|एनीडेस्क|टीमव्यूअर|apk[^.!?]{0,15}डाउनलोड|डाउनलोड\s*कर\w*/.test(t),
  },
  {
    id: "boss_impersonation",
    weight: 2.3,
    why: "Someone claiming to be your boss or a colleague is asking for money or data from an unfamiliar address. Verify on a channel you already trust before acting.",
    test: (t) =>
      /\b(?:this\s*is\s*(?:your\s*)?(?:ceo|manager|director|boss|hr)|i(?:'m| am)\s*(?:your\s*)?(?:ceo|manager|boss)|new\s*(?:number|email)[^.!?]{0,30}\b(?:this\s*is|it'?s)\b)/.test(t) ||
      (/\b(?:ceo|manager|director|boss)\b/.test(t) && /\b(?:urgent|discreet|favou?r|right\s*now|quick\s*task)\b/.test(t)) ||
      // "बॉस बोल रहा हूं" (this is your boss speaking) — the authority title
      // is a Devanagari-spelled loanword even in an otherwise Hindi message.
      (/बॉस|मैनेजर|डायरेक्टर/.test(t) && /बोल\s*रहा|बोल\s*रही|अर्जेंट|जल्दी/.test(t)),
  },
  {
    id: "payment_detail_change",
    weight: 2.5,
    why: "It asks to redirect a payment to different bank details. This is how invoice-redirection fraud works — always confirm by phone using a number you already have.",
    test: (t) =>
      // `(?:your\s*)?` because "Update your billing info" puts the possessive
      // between the verb and the noun, and \s* only spans whitespace.
      /\b(?:updated?|new|changed?|different)\s*(?:your\s*)?(?:bank(?:ing)?|account|payment|remittance|wire|billing)\s*(?:details|information|info|number)\b/.test(t) ||
      // The English half of the payroll redirect already fixed in Devanagari.
      // Not sentence-gated for the same reason as above — "our payroll portal
      // changed. Re-register your salary account on the new site" splits the
      // claim and the instruction across a full stop.
      (/\b(?:payroll|salary)\s*(?:account|portal|details)\b/.test(t) &&
        /\b(?:re-?register|re-?enter|update|chang(?:e|ed)|new\s*(?:site|portal|link))\b/.test(t)) ||
      // "Bank details bhejiye" — the ask with no "updated/new" adjective in
      // front of it, which is the only form the English pattern above matches.
      new RegExp(`\\bbank\\s*details?\\b[^.!?]{0,30}(?:${HI.send}|send|share)`).test(t) ||
      /\bchange\s*(?:the\s*)?(?:bank|payment)\s*details\b/.test(t) ||
      // "वेंडर का बैंक अकाउंट बदल गया है", "बैंक डिटेल दोबारा वेरिफाई करें"
      // सैलरी/पेरोल belong beside बैंक here: a payroll-redirect scam asks you to
      // re-register your *salary* account, never your "bank account", so the
      // noun list as written could not match the payroll variant at all.
      /(?:बैंक|सैलरी|पेरोल|payment)\s*(?:अकाउंट|एकाउंट|डिटेल|account|खाता|पासबुक)[^.!?]{0,30}(?:बदल|अपडेट|दोबारा|verify|वेरिफाई|सत्यापित|भर|डाल|लिंक|जोड़|रजिस्टर|अपलोड)/.test(t) ||
      // An IFSC code identifies a bank branch and has exactly one reason to be
      // asked for: routing money. Paired with a verb it is the harvest, whether
      // or not the message ever says "bank account" — a bonus-distribution
      // pretext asks for "IFSC कोड और खाता नंबर" with no such phrase in it.
      /(?:ifsc|आईएफएससी)[^।.!?]{0,45}(?:सत्यापित|वेरिफाई|भर|डाल|अपलोड|शेयर|फॉर्म|भेज)/.test(t),
  },
  {
    id: "family_emergency",
    weight: 2.4,
    why: "Someone claiming to be family or a friend is asking for money, from an unfamiliar number or during a sudden crisis. This is the most effective scam there is, because it works on affection rather than fear: call the person on the number you already have for them before you send anything.",
    test: (t) => {
      // Three parts, and the third is what makes it a scam rather than a
      // Tuesday. "Hi mum, this is my new number" is a real message people
      // really send; so is "bro, send me the wedding photos". Only the
      // combination of a claimed relationship, an actual request for money,
      // and either an unverifiable number or a sudden crisis is the tactic.
      const relationship =
        /\b(?:mum|mom|dad|papa|mummy|beta|bro|sis|son|daughter|uncle|aunt(?:y|ie)?|grand(?:ma|pa)|it'?s\s*me)\b/.test(t) ||
        // माँ (with chandrabindu) and मां (with anusvara) are both common,
        // interchangeable spellings of "mom" — only the first was covered.
        /पापा|माँ|मां|मम्मी|बेटा|बेटी|भाई|बहन|चाचा|मामा|दादी|दादा|दीदी|मैं\s*हूँ/.test(t) ||
        /\b(?:main\s*hoon|bhai|behen|didi|chacha|mama|nana|nani)\b/.test(t);
      if (!relationship) return false;

      // NOTE: normalize() folds digits onto letters to defeat homoglyphs, so
      // "8000" arrives as "8ooo". Never match \d in a heuristic — the amount
      // has to be recognised by the words around it.
      const wantsMoney =
        (/\b(?:send|transfer|pay|paying|need|deposit|lend|credit)\b/.test(t) &&
          /\b(?:money|cash|rs|inr|rupees|upi|gpay|paytm|phonepe|amount|rent|fees?|funds?|account)\b/.test(t)) ||
        new RegExp(`(?:${HI.send}|transfer|bhijwa\\w*)[^.!?]{0,30}(?:${HI.money})`).test(t) ||
        new RegExp(`(?:${HI.money})[^.!?]{0,30}(?:${HI.send}|transfer|chahiye|चाहिए|मांग)`).test(t) ||
        // Devanagari messages often name the amount and a bare send/deposit
        // verb without a currency word in between ("3000 भेज दो") — the
        // digit itself would carry that signal in English but normalize()
        // folds it away, so a relationship term plus a bare transmission
        // verb has to be enough on its own here. "मांग" (asking/demanding)
        // covers the third-person framing — "the doctor is asking for
        // 18000 rupees right now" — where nobody says "send" at all.
        new RegExp(`${HI.send}|मांग`).test(t);
      if (!wantsMoney) return false;

      const unreachable =
        /\b(?:new|different|temp(?:orary)?|another|friend'?s|borrowed)\s*(?:number|phone|mobile|sim)\b|lost\s*my\s*(?:phone|wallet)|broke\s*my\s*(?:phone|screen)|texting\s*from\b/.test(t) ||
        /\b(?:nay[ae]|naya|dusre)\s*(?:number|phone|sim)|phone\s*kho\s*gaya|number\s*badal/.test(t) ||
        // "नए?" (matching bare "न" or "नए") never matches "नया नंबर" — नया
        // is the direct-case form of "new" that precedes a masculine
        // singular noun like नंबर, and नए is the oblique/plural form used
        // before postpositions like "से". Real messages say "नया नंबर".
        // "टेम्परेरी" (temporary) is the English loanword spelled in
        // Devanagari, not a translation — a real message says "टेम्परेरी
        // नंबर" at least as often as "नया नंबर", and only the latter was
        // covered.
        /न[ईएय][ां]?\s*(?:नंबर|सिम|फ़?ोन|मोबाइल)|टेम्परेरी\s*(?:नंबर|सिम|फ़?ोन|मोबाइल)|फ़?ोन\s*खो\s*गया|दूसरे\s*नंबर|दोस्त\s*के\s*(?:नंबर|फ़?ोन)\s*से/.test(t);
      const crisis =
        /\b(?:accident|hospital|emergency|surgery|operation|admitted|icu|stuck|stranded|detained|arrested|police\s*station|urgent(?:ly)?|tonight|right\s*(?:now|away))\b/.test(t) ||
        new RegExp(`\\b(?:${HI.urgentLatin})\\b|${HI.urgentDevanagari}|दुर्घटना|अस्पताल|एक्सीडेंट|ऑपरेशन|भर्ती|फंसा|अटका|चोरी`).test(t);

      return unreachable || crisis;
    },
  },
  {
    id: "delivery_redispatch_fee",
    weight: 2.0,
    why: "It says a delivery needs money or re-confirmation before it can reach you. Couriers do not charge you to re-attempt a delivery — the fee is the scam, and the page that collects it collects your card.",
    test: (t) => {
      if (
        !/\b(?:deliver(?:y|ed|ies)?|dispatch|shipment)\b/.test(t) &&
        !new RegExp(HI.parcel).test(t)
      ) {
        return false;
      }

      // Any two of these three. One alone is ordinary logistics: real couriers
      // say "delivered", real tracking pages say "reschedule", and real orders
      // have charges. Two together is the redispatch-fee pattern.
      //
      // Note the missing \b after prefixes like "reschedul" — a trailing \b
      // there requires a boundary between "l" and "e" and can never match
      // "reschedule".
      const failed =
        /\b(?:could\s*not|couldn'?t|cannot|can'?t|failed|unsuccessful|unable\s*to|attempt(?:ed)?|on\s*hold|pending|held|suspended|incomplete|incorrect\s*address)\b|address\s*verification/.test(t) ||
        /रुका|अटका|लंबित|पेंडिंग|होल्ड/.test(t);
      const action =
        /reschedul|re-?dispatch|re-?deliver|\bconfirm|\bverif|update\s*your\s*address/.test(t) ||
        /रिलीज़|दोबारा\s*भेज|पता\s*अपडेट|अपडेट\s*कर/.test(t);
      const payment =
        /\b(?:pay|paying|payment|fees?|charges?|deposit|customs|duty)\b/.test(t) ||
        new RegExp(`${HI.fee}|भर(?:कर|ें|ना|ो)?`).test(t);

      return [failed, action, payment].filter(Boolean).length >= 2;
    },
  },
  {
    id: "job_advance_fee",
    weight: 2.2,
    why: "It offers work but asks you to pay first — a deposit, registration, or kit charge. Real employers pay you; they never ask you to pay them to start.",
    test: (t) =>
      (/\b(?:job|work\s*from\s*home|part[\s-]?time|data\s*entry|hiring|vacancy|earn|salary|income|packing|typing|recruit)\b/.test(t) ||
        /\b(?:ghar\s*baithe|kaam\s*kar|kama(?:iye|ye|o)|naukri)\b/.test(t) ||
        // Real Devanagari-script job scams routinely spell the job itself in
        // Devanagari letters ("जॉब", "इंटरव्यू", "टास्क") rather than using
        // the Hindi words for it — these are loanwords, not translations.
        /घर\s*बैठे|काम\s*कर|कमा(?:एं|इए|ओ)|नौकरी|जॉब|इंटरव्यू|सिलेक्ट|सैलरी|पार्ट\s*टाइम|टास्क|वर्क\s*फ्रॉम\s*होम/.test(t)) &&
      (/\b(?:pay|deposit|paying|charge|fee|amount|registration|security|refundable|membership|joining|advance)\b/.test(t) ||
        new RegExp(`${HI.fee}|${HI.money}|registration|रजिस्ट्रेशन|जॉइनिंग|किट`).test(t)) &&
      // No \d here on purpose: normalize() folds digits onto letters, so an
      // amount arrives as "soo" rather than "500". The charge is identified by
      // what it is called, not by the number attached to it.
      (/\b(?:registration|security|refundable|membership|joining|processing|courier|kit|training|advance|one[\s-]?time)\b[^.!?]{0,20}\b(?:fee|deposit|charge|amount|payment|of)\b|\b(?:pay|deposit)\b[^.!?]{0,25}\b(?:rs|inr|registration|deposit|membership)\b/.test(t) ||
        // "registration ke liye 500 bhejiye", "रजिस्ट्रेशन के लिए 500 भेजें",
        // "जॉइनिंग किट के लिए 999 रुपये" (no explicit fee/send word, just a
        // named cost near a rupee amount — the amount stands in for one).
        // The named-cost list was Devanagari-only for words that real messages
        // write in Devanagari, and missed the ones they write as Devanagari-
        // spelled loanwords: सिक्योरिटी (security deposit), एक्टिवेशन (account
        // activation), अनलॉक (unlocking the first "task"). "ID कार्ड" is also
        // routinely written mixed-script — Latin "ID" against Devanagari
        // "कार्ड" — which neither `आईडी` nor `id\s*card` could match.
        new RegExp(
          `(?:registration|रजिस्ट्रेशन|deposit|जॉइनिंग|किट|वेरिफिकेशन|यूनिफॉर्म|आईडी|id\\s*(?:card|कार्ड)|सिक्योरिटी|एक्टिवेशन|अनलॉक|${HI.fee})[^.!?]{0,30}(?:${HI.send}|bhar|भर|${HI.money})`
        ).test(t)),
  },
  {
    id: "refund_callback",
    weight: 1.8,
    why: "It reports a charge you don't recognise and gives a number to call to cancel it. The number reaches the scammer, who will talk you into remote access or a transfer to \"refund\" you.",
    test: (t) =>
      // Each of the three clauses had a Devanagari half that covered one
      // spelling and missed the neighbouring one: "कट गया" but not "कटा",
      // "कॉल कर" but not "कॉलबैक", and no word for refund or cancel at all —
      // which are the two nouns this tactic is *about*.
      (/\b(?:auto[\s-]?renew(?:ed|al)?|subscription|invoice|order|debited|charged|transaction|purchase|renewal)\b/.test(t) ||
        /\bdebit\s*hua|कट\s*(?:गया|गई)|कटा\s*है|कटे\s*हैं|डेबिट\s*हुआ|खाते\s*से|सब्सक्रिप्शन|ट्रांजैक्शन/.test(t)) &&
      (/\b(?:call|dial|contact|helpline|toll[\s-]?free|customer\s*(?:care|support)|reach\s*us)\b/.test(t) ||
        /नंबर\s*पर\s*कॉल|number\s*par\s*call|कॉल\s*(?:कर|बैक)|कॉलबैक|कस्टमर\s*केयर|एग्जीक्यूटिव/.test(t)) &&
      (/\b(?:cancel|refund|dispute|unauthori[sz]ed|not\s*(?:authori[sz]ed|you|recognise|recognize)|if\s*this\s*(?:was|is)\s*not|to\s*stop)\b/.test(t) ||
        /agar\s*aapne\s*nahi|यदि\s*आपने\s*नहीं|अगर\s*आपने\s*नहीं|nahi\s*kiya|रिफ़?ंड|कैंसिल|वापस\s*(?:पाने|पान)/.test(t)),
  },
  {
    id: "investment_scam",
    weight: 2.2,
    why: "It promises a guaranteed or unusually high return on an investment. Real investments carry risk — nobody can guarantee a return, and this is the setup for a payout that never comes.",
    test: (t) =>
      // "guarantee(s/d) ... return/profit/income" gated within a sentence,
      // not requiring the words to sit directly next to each other — real
      // pitches say "guarantees 40 percent monthly returns", not "guaranteed
      // return". The old \bguarantee(?:d)?\s*(?:return|profit|income)\b
      // matched neither: no plural "guarantees", and \s* meant zero or more
      // *whitespace* characters, not zero or more words — "returns" itself
      // was also never matched since the noun side had no plural either.
      /\bguarantee[ds]?\b[^.!?]{0,30}\b(?:returns?|profits?|income)\b/.test(t) ||
      /double\s*(?:your\s*)?money|assured\s*returns?/.test(t) ||
      // गारंटीड रिटर्न / पैसा डबल / डेली प्रॉफिट — none of this needs a
      // digit to be recognisable, which matters because normalize() folds
      // digits onto letters ("40%" survives as letters, not as "40").
      /गारंटीड?\s*रिटर्न|एश्योर्ड\s*रिटर्न|पैसा\s*डबल|डेली\s*प्रॉफिट|मल्टीबैगर|गारंटी[^.!?]{0,20}(?:रिटर्न|प्रॉफिट|एलॉटमेंट)/.test(t) ||
      ((/\b(?:invest(?:ment)?|trading|stock|share|mutual\s*fund|scheme|ipo)\b/.test(t) ||
        /इन्वेस्ट|ट्रेडिंग|म्यूचुअल\s*फंड|स्टॉक\s*टिप्स|आईपीओ/.test(t)) &&
        new RegExp(`${HI.money}|profit|return|scheme|स्कीम|vip\\s*ग्रुप|रिटर्न`).test(t)),
  },
  {
    id: "windfall_solicitation",
    weight: 2.2,
    why: "A stranger says they want to move a large sum of money through you, usually with a story about illness, war, or a dead relative. The story is a script, and the money does not exist.",
    test: (t) =>
      /\b(?:million|billion|crore|lakh|fortune|inheritance|estate|fund(?:s)?|sum\s*of\s*money|deposit\s*of)\b/.test(t) &&
      /\b(?:widow|terminal(?:ly)?\s*ill|dying|late\s*husband|deceased|next\s*of\s*kin|beneficiar(?:y|ies)|barrister|army\s*officer|deployed|refugee|orphan|god[\s-]?fearing|trusted\s*partner|business\s*proposal)\b/.test(t) ||
      // The "posted army officer selling his furniture, send an advance"
      // approach is a staple of Indian classifieds fraud.
      /\b(?:army\s*officer|fauji|transfer\s*ho\s*gaya)\b|सेना\s*अधिकारी|विधवा/.test(t),
  },
  {
    id: "generic_salutation",
    weight: 0.5,
    why: "It opens with a generic greeting instead of your name — typical of a message blasted to thousands of addresses.",
    test: (t) => /^(?:dear\s*(?:customer|user|client|sir\/?\s*madam|account\s*holder|member)|attention\s*customer|hello\s*dear)\b/.test(t),
  },
  {
    id: "reply_to_mismatch_language",
    weight: 0.9,
    why: "It pushes you to reply to a different address or call a number in the message rather than using the company's published contact details.",
    test: (t) =>
      /\b(?:reply\s*(?:to\s*this|with)|call\s*(?:us\s*)?(?:on|at|immediately)|contact\s*(?:us\s*)?(?:on|at)|whatsapp\s*(?:us|me|on))\b/.test(t) &&
      /\b(?:immediately|urgent|within|now|asap|24\s*hours)\b/.test(t),
  },
];

// Signals that a message is *legitimate*. Without these, ordinary business
// mail that happens to say "urgent" gets flagged, and false positives are what
// make people uninstall a tool like this.
const EXONERATING_RULES = [
  {
    id: "conversational_context",
    weight: -1.0,
    why: "It reads like an ongoing conversation rather than a cold approach.",
    test: (t) =>
      /\b(?:as\s*(?:we\s*)?discussed|per\s*(?:our|your)\s*(?:last\s*)?(?:call|email|message|conversation)|following\s*up\s*on|thanks\s*for\s*(?:the|your)|re:\s|you\s*mentioned|attached\s*(?:is|are)\s*the)\b/.test(t),
  },
  {
    id: "no_action_requested",
    weight: -0.8,
    why: "It doesn't ask you to click, pay, or hand over anything.",
    // An exonerating rule that tests for the *absence* of English verbs fires
    // on every message not written in English, which means it was handing a
    // discount to exactly the Hindi and Hinglish scams the rules above exist to
    // catch. A Devanagari message demanding an OTP scored 21 instead of 44 for
    // this reason. Absence-based rules have to know every language the
    // presence-based ones do, or they quietly invert.
    // The Devanagari verb list drifted behind the presence-based rules again,
    // exactly as the note above predicts. `कर(?:िए|ें|ो)` matched "करें" but
    // not "करना", "करवाइए" or "करके", and there was no entry for भरें (fill
    // in), अपलोड (upload), लॉगिन (log in) or सत्यापित (verify) at all — so a
    // scam saying "फॉर्म तुरंत भरें" or "नेट बैंकिंग लॉगिन करें" read as
    // asking for nothing and collected the discount. Four of the ten remaining
    // Devanagari misses were being helped over the line by this rule.
    test: (t) =>
      !new RegExp(
        "\\b(?:click|tap|verify|confirm|login|log\\s*in|sign\\s*in|pay|send|transfer|share|download|install|call|reply\\s*with|update\\s*your)\\b" +
          `|${HI.send}|${HI.tell}|${HI.enter}|kar(?:iye|ein|o)\\b|कर(?:िए|ें|ो|ना|वा|के)|कॉल|क्लिक|अपडेट` +
          "|भर(?:ें|िए|ना|कर|ो)|अपलोड|लॉगिन|वेरिफ|सत्यापित|भुगतान|दीजिए|दीजिये"
      ).test(t),
  },
  {
    id: "internal_scheduling",
    weight: -0.7,
    why: "It's about scheduling or routine coordination.",
    test: (t) =>
      /\b(?:meeting|standup|stand-up|sync|calendar\s*invite|reschedul|agenda|1:1|retro|sprint|pull\s*request|code\s*review|merge\s*request)\b/.test(t),
  },
];

/**
 * @param {string} rawText
 * @param {{hasCredentialForm?: boolean}} [context] What the text is. A page
 *   carrying an actual login form is read differently from a message that
 *   merely talks about one.
 * @returns {{score: number, signals: Array<{id, weight, detail}>, exonerating: Array}}
 */
export function analyzeHeuristics(rawText, context = {}) {
  // Drop the separators *inside* a number before normalizing. Almost every
  // rule below gates on `[^.!?]{0,N}` to mean "within one sentence", and
  // normalize() folds digits onto letters but leaves their punctuation alone —
  // so "Rs 2,450.00" arrives as "rs 2,aso.oo" and "1.5 लाख" as "l.s लाख", each
  // carrying a full stop that splits the sentence in half and puts the two
  // halves of a rule out of reach of each other. A real advance-fee scam
  // ("आपका 1.5 लाख अप्रूव हुआ है, GST क्लियरेंस के लिए 750 रुपये भेजें") went
  // unflagged for exactly this reason: the decimal point in the amount, not
  // anything about the sentence.
  //
  // Done here rather than in normalize(), which is shared with the tokenizer
  // and must keep matching train_model.py's — see tests/test_parity.py. And
  // done before folding, because afterwards "1.5" reads as "l.s" and is no
  // longer distinguishable from an abbreviation.
  // Curly apostrophes fold to straight ones for the same reason. Gmail, Word
  // and iOS all autocorrect ' to U+2019, so real mail overwhelmingly carries
  // the curly form, and normalize() passes it through untouched — every
  // pattern written with an ASCII apostrophe silently stopped matching the
  // text it was written for. "You’ve won a free iPhone! Click the link to
  // claim now." tripped no rule at all, because `you(?:'ve| have)?` cannot see
  // the character actually in the string. The same held for don’t, can’t,
  // couldn’t, it’s, I’m and friend’s across five other rules.
  const t = normalize(
    rawText.replace(/(?<=\d)[.,](?=\d)/g, "").replace(/[‘’ʼ´`]/g, "'")
  );
  const signals = [];
  const exonerating = [];

  for (const rule of RULES) {
    if (rule.test(t, context)) {
      signals.push({ id: rule.id, weight: rule.weight, detail: rule.why });
    }
  }

  // Exonerating rules only apply when nothing severe fired — "as discussed,
  // send me your OTP" should not get a discount.
  const hasSevere = signals.some((s) => s.weight >= 2.0);
  if (!hasSevere) {
    for (const rule of EXONERATING_RULES) {
      if (rule.test(t)) {
        exonerating.push({ id: rule.id, weight: rule.weight, detail: rule.why });
      }
    }
  }

  const score =
    signals.reduce((sum, s) => sum + s.weight, 0) +
    exonerating.reduce((sum, s) => sum + s.weight, 0);

  return { score: Math.max(0, score), signals, exonerating };
}

export const RULE_COUNT = RULES.length;
