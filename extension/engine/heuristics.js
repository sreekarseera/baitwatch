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
// (see INDIC_MARKS in lib/text.js), but the model layer is still the one that
// contributes nothing on Hindi script — the corpus has too few Devanagari rows
// for a single Hindi term to reach the vocabulary. These rules remain the only
// thing standing between a Hindi-script scam and the user.
//
// Transliteration has no agreed spelling — "bhejiye", "bhejo", "bhej do" are
// one word — so stems are used where the stem is distinctive enough to be safe
// on its own. "bhej" is; "kar" (do) would not be, and is never used alone.
// ---------------------------------------------------------------------------
const HI = {
  // send / give / tell — the transmission verbs. "जमा" (deposit/submit) is
  // how a fee gets sent, not a way of sending it, but the two read the same
  // to whoever pays, so it belongs with the other transmission verbs.
  send: "bhej\\w*|भेज\\w*|de\\s*do|दे\\s*दो|jama\\w*|जमा",
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
  blocked:
    "band\\s*ho|block\\s*ho|suspend|nilambit|बंद\\s*हो|ब्लॉक|निलंबित|समाप्त|" +
    "रोक(?:ा|ी|दिया)?|काम\\s*नहीं\\s*करेगा",
  // ड्यूटी (duty) is how a customs/import charge is actually named in
  // Devanagari SMS — "शुल्क" is formal-register Hindi that real scam
  // messages use rarely.
  fee: "shulk|शुल्क|फ़?ीस|charge|fee|duty|ड्यूटी|चार्ज|क्लियरेंस",
  police:
    "cyber\\s*cell|साइबर\\s*सेल|cbi|सीबीआई|police|पुलिस|warrant|वारंट|giraftar|गिरफ़?्तार|थाना|थाने|" +
    "\\bed\\b|ईडी|फेमा|supreme\\s*court|सुप्रीम\\s*कोर्ट|money\\s*laundering|मनी\\s*लॉन्ड्रिंग|दूरसंचार",
  prize: "lotter[iy]|लॉटरी|jeet\\s*ga(?:ye|ya)|जीत\\s*ग(?:ए|या)|badhai|बधाई|inaam|इनाम",
  kyc: "kyc|केवाईसी",
  // Parcel/courier vocabulary, Devanagari and Devanagari-spelled loanwords —
  // delivery_redispatch_fee had no Hindi-script coverage at all before this.
  // कस्टम(?!र) excludes "कस्टमर" (customer) — कस्टम (customs) is its own
  // word but also happens to be the first four characters of the routine
  // word for "customer", and a bare substring match can't tell them apart.
  parcel: "parcel|package|courier|consignment|पार्सल|पैकेट|कूरियर|कोरियर|कस्टम(?!र)|कंसाइनमेंट",
};

const CREDENTIAL_NOUN_RE =
  /\b(?:password|passcode|pin(?:\s*(?:number|code))?|otp|one[\s-]?time\s*(?:password|code|pin)|cvv|card\s*(?:number|details)|security\s*code|seed\s*phrase|recovery\s*phrase|private\s*key|aadhaar|ssn|social\s*security)\b|ओटीपी|पिन|आधार|पासवर्ड/;

// The secret leaving your possession, *towards whoever is asking*. The
// direction is the whole signal: "send OTP to your registered mobile" is a real
// bank's own button and "send me your OTP" is a theft, and both contain "send".
// So the verb has to carry an indirect object pointing back at the sender. Bare
// verbs matched far too much — including the word "email" sitting on the login
// form of every site in the world.
const CREDENTIAL_TRANSMIT_RE = new RegExp(
  "\\b(?:(?:send|forward|give|tell|text|whatsapp|email|message)\\s+(?:it\\s+)?(?:me|us|back|to\\s+(?:me|us))" +
    "|share\\s+(?:your|the|it|with)|reply\\s+(?:with|back\\s+with)|revert\\s+with|provide\\s+(?:me|us))\\b" +
    // Hinglish has no indirect-object cue to lean on the way English does:
    // "OTP bhejiye" is already the entire request, with no "me" in it. The
    // imperative form carries the direction on its own.
    `|${HI.send}|${HI.tell}`
);

// Verbs that describe typing a secret into a form. Damning in a message,
// unremarkable on the login page it describes — see the rule below.
const CREDENTIAL_ENTRY_RE = new RegExp(
  `\\b(?:enter|provide|confirm|verify|submit|update)\\b|${HI.enter}`
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
      // On a page that has a real login form, "enter your password" is what
      // every legitimate sign-in page in the world says. Judged as a message
      // it reads as a credential request, which made the rule fire on the
      // genuine bank and workplace logins the whole-page scan exists to check.
      // There, only asking you to *transmit* the secret counts.
      return ctx.hasCredentialForm
        ? CREDENTIAL_TRANSMIT_RE.test(t)
        : CREDENTIAL_TRANSMIT_RE.test(t) || CREDENTIAL_ENTRY_RE.test(t);
    },
  },
  {
    id: "gift_card_payment",
    weight: 3.0,
    why: "It asks for payment in gift cards. Gift cards are untraceable and are the single most common scam payment method — no legitimate business, agency, or manager collects payment this way.",
    test: (t) =>
      /\b(?:gift\s*card|itunes\s*card|steam\s*(?:card|wallet)|google\s*play\s*card|voucher\s*code|prepaid\s*card)\b/.test(t) ||
      // "Google Play गिफ्ट कार्ड" — the brand stays in Latin script but the
      // "gift card" itself is routinely spelled out in Devanagari.
      /गिफ्ट\s*कार्ड|आइट्यून्स|स्टीम\s*कार्ड|वाउचर/.test(t),
  },
  {
    id: "crypto_transfer",
    weight: 2.4,
    why: "It asks you to send cryptocurrency. Crypto payments cannot be reversed or recovered once sent.",
    test: (t) =>
      /\b(?:bitcoin|btc|ethereum|eth|usdt|crypto(?:currency)?|wallet\s*address)\b/.test(t) &&
      /\b(?:send|transfer|deposit|invest|double|pay|scan)\b/.test(t),
  },
  {
    id: "upi_collect_request",
    weight: 2.6,
    why: "It asks you to approve a UPI request or scan a QR code to *receive* money. Approving a UPI request or scanning a QR code always sends money out of your account — it never brings money in.",
    test: (t) =>
      new RegExp(`\\b(?:upi|gpay|google\\s*pay|phonepe|paytm|bhim|qr\\s*code)\\b|यूपीआई|क्यूआर|कलेक्ट\\s*रिक्वेस्ट`).test(t) &&
      new RegExp(
        `\\b(?:collect\\s*request|accept|approve|scan|enter\\s*(?:your\\s*)?pin|receive|refund|cashback)\\b` +
        `|${HI.enter}|स्वीकार|स्कैन|एक्सेप्ट`
      ).test(t),
  },
  {
    id: "account_suspension",
    weight: 1.5,
    why: "It claims your account is suspended, locked, or about to be closed. Manufactured account trouble is the standard hook for stealing logins.",
    test: (t) =>
      /\b(?:account|card|profile|subscription|service)\b[^.!?]{0,40}\b(?:suspend(?:ed)?|lock(?:ed)?|block(?:ed)?|disabl(?:ed)?|deactivat(?:ed)?|restrict(?:ed)?|clos(?:ed|ure)|terminat(?:ed)?|on\s*hold)\b/.test(t) ||
      // "aapka khata band ho jayega", "KYC expire ho gaya hai"
      new RegExp(`(?:${HI.account}|${HI.kyc})[^.!?]{0,40}(?:${HI.blocked}|expire|khatam|खत्म)`).test(t) ||
      new RegExp(`(?:${HI.kyc})[^.!?]{0,25}(?:expire|समाप्त|pending|update)`).test(t),
  },
  {
    id: "artificial_urgency",
    weight: 1.2,
    why: "It sets a countdown. Deadlines like this exist to stop you checking with someone before you act.",
    test: (t) =>
      /\b(?:within\s*\d+\s*(?:hour|hr|minute|min|day)|in\s*the\s*next\s*\d+\s*(?:hour|minute)|before\s*(?:midnight|today|tonight|it\s*expires)|expir(?:es|ing)\s*(?:today|soon|in)|last\s*(?:chance|warning)|final\s*(?:notice|warning|reminder)|immediately|right\s*away|act\s*now|urgent(?:ly)?|asap)\b/.test(t) ||
      new RegExp(`\\b(?:${HI.urgentLatin})\\b|${HI.urgentDevanagari}|आज\\s*रात|aaj\\s*raat`).test(t),
  },
  {
    id: "threat_of_consequence",
    weight: 1.7,
    why: "It threatens arrest, legal action, or a fine. Real agencies send written notices; they do not threaten you over email or chat.",
    test: (t) =>
      /\b(?:arrest(?:ed)?|legal\s*action|lawsuit|court|police|fir\b|warrant|prosecut(?:e|ion)|penalt(?:y|ies)|fine|seiz(?:e|ed|ure)|deport|jail|criminal\s*(?:case|charge))\b/.test(t) ||
      new RegExp(`${HI.police}|मामला\\s*दर्ज|case\\s*darj|थाना|थाने|चालान|जमानत`).test(t),
  },
  {
    id: "prize_or_windfall",
    weight: 1.9,
    why: "It says you've won something you never entered, or money is waiting for you. Unsolicited winnings are a lure to collect your details or an upfront \"fee\".",
    test: (t) =>
      /\b(?:you(?:'ve| have)?\s*(?:been\s*)?(?:won|win|selected|chosen)|congratulations|lucky\s*winner|claim\s*your\s*(?:prize|reward|gift)|lottery|jackpot|unclaimed\s*(?:funds|money|refund)|inherit(?:ance|ed))\b/.test(t) ||
      new RegExp(HI.prize).test(t) ||
      // Devanagari-spelled loanwords for the same "unexpected money is
      // waiting" lure — refunds, reward points, cashback, and bonuses that
      // were never earned, not the classic lottery framing. Gated on a
      // nearby call to action: a bank routinely says "cashback credited,
      // refund will arrive in 5 days" with nothing for the reader to do,
      // and that has to read as the routine notice it is. The scam version
      // always asks for a click, a claim, or a form.
      new RegExp(`(?:रिफंड|रिवॉर्ड|बोनस|कैशबैक|पॉइंट्स)[^.!?]{0,45}(?:क्लेम|रिडीम|लिंक|apk|डाउनलोड|फॉर्म|वेरिफ|एक्सपायर|पिन)`).test(t),
  },
  {
    id: "advance_fee",
    weight: 2.0,
    why: "It asks for a payment up front to release a larger sum. That larger sum does not exist.",
    test: (t) =>
      /\b(?:processing\s*fee|clearance\s*fee|customs\s*(?:fee|duty|charge)|release\s*fee|registration\s*fee|handling\s*charge|small\s*(?:fee|amount)|refundable\s*deposit)\b/.test(t) ||
      // "processing fee bhejiye", "clearance shulk bharkar", "file charge 999"
      new RegExp(`(?:${HI.fee})[^.!?]{0,25}(?:${HI.send}|bhar|भर|pay)|(?:file|delivery|clearance|क्लियरेंस|processing)\\s*(?:${HI.fee})`).test(t) ||
      // Loan-advance-fee scams name the up-front cost without a fee word at
      // all — "GST क्लियरेंस के लिए 750 रुपये", "स्टाम्प ड्यूटी" — the
      // charge is identified by what it's for, next to a rupee amount.
      new RegExp(`(?:लोन|loan)[^.!?]{0,60}(?:क्लियरेंस|स्टाम्प|clearance|stamp)[^.!?]{0,20}(?:${HI.money})`).test(t),
  },
  {
    id: "impersonated_authority",
    weight: 1.4,
    why: "It claims to be from a bank, tax office, or support desk. Check by contacting them yourself using a number you already have — never one from the message.",
    test: (t) =>
      /\b(?:income\s*tax|irs\b|hmrc|customs|cyber\s*cell|trai\b|rbi\b|federal|government|microsoft\s*support|apple\s*support|tech\s*support|security\s*team|fraud\s*department)\b/.test(t) ||
      new RegExp(`${HI.police}|bank\\s*se\\s*bol|बैंक\\s*से\\s*बोल|hr\\s*se\\s*bol|कस्टम(?!र)|इनकम\\s*टैक्स|आयकर`).test(t),
  },
  {
    id: "secrecy_request",
    weight: 2.1,
    why: "It tells you to keep this quiet or not to contact anyone. Isolating you from a second opinion is a deliberate tactic, not a business practice.",
    test: (t) =>
      /\b(?:do\s*not\s*(?:tell|inform|discuss|share\s*this)|keep\s*(?:this|it)\s*(?:confidential|secret|between\s*us)|don'?t\s*(?:tell|call|contact)\s*(?:anyone|police|bank)|without\s*informing)\b/.test(t) ||
      // "kisi ko mat bataiyega", "police ko mat bataana"
      new RegExp(`(?:kisi\\s*ko|police\\s*ko|किसी\\s*को|पुलिस\\s*को)\\s*(?:mat|nahi|मत|नहीं)`).test(t),
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
      /रिमोट\s*एक्सेस|एनीडेस्क|टीमव्यूअर|apk\s*डाउनलोड|डाउनलोड\s*(?:करें|कीजिए)/.test(t),
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
      /\b(?:updated?|new|changed?|different)\s*(?:bank(?:ing)?|account|payment|remittance|wire)\s*(?:details|information|info|number)\b/.test(t) ||
      /\bchange\s*(?:the\s*)?(?:bank|payment)\s*details\b/.test(t) ||
      // "वेंडर का बैंक अकाउंट बदल गया है", "बैंक डिटेल दोबारा वेरिफाई करें"
      /(?:बैंक|payment)\s*(?:अकाउंट|एकाउंट|डिटेल|account)[^.!?]{0,20}(?:बदल|अपडेट|दोबारा|verify|वेरिफाई|भर|डाल|लिंक|जोड़)/.test(t),
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
        /न[ईएय][ां]?\s*(?:नंबर|सिम|फ़?ोन|मोबाइल)|फ़?ोन\s*खो\s*गया|दूसरे\s*नंबर|दोस्त\s*के\s*(?:नंबर|फ़?ोन)\s*से/.test(t);
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
        new RegExp(
          `(?:registration|रजिस्ट्रेशन|deposit|जॉइनिंग|किट|वेरिफिकेशन|यूनिफॉर्म|आईडी|id\\s*card|${HI.fee})[^.!?]{0,30}(?:${HI.send}|bhar|भर|${HI.money})`
        ).test(t)),
  },
  {
    id: "refund_callback",
    weight: 1.8,
    why: "It reports a charge you don't recognise and gives a number to call to cancel it. The number reaches the scammer, who will talk you into remote access or a transfer to \"refund\" you.",
    test: (t) =>
      (/\b(?:auto[\s-]?renew(?:ed|al)?|subscription|invoice|order|debited|charged|transaction|purchase|renewal)\b/.test(t) ||
        /\bdebit\s*hua|कट\s*गया|डेबिट\s*हुआ|खाते\s*से/.test(t)) &&
      (/\b(?:call|dial|contact|helpline|toll[\s-]?free|customer\s*(?:care|support)|reach\s*us)\b/.test(t) ||
        /नंबर\s*पर\s*कॉल|number\s*par\s*call|कॉल\s*कर/.test(t)) &&
      (/\b(?:cancel|refund|dispute|unauthori[sz]ed|not\s*(?:authori[sz]ed|you|recognise|recognize)|if\s*this\s*(?:was|is)\s*not|to\s*stop)\b/.test(t) ||
        /agar\s*aapne\s*nahi|यदि\s*आपने\s*नहीं|अगर\s*आपने\s*नहीं|nahi\s*kiya/.test(t)),
  },
  {
    id: "investment_scam",
    weight: 2.2,
    why: "It promises a guaranteed or unusually high return on an investment. Real investments carry risk — nobody can guarantee a return, and this is the setup for a payout that never comes.",
    test: (t) =>
      /\bguarantee(?:d)?\s*(?:return|profit|income)\b|double\s*(?:your\s*)?money|assured\s*returns?/.test(t) ||
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
    test: (t) =>
      !new RegExp(
        "\\b(?:click|tap|verify|confirm|login|log\\s*in|sign\\s*in|pay|send|transfer|share|download|install|call|reply\\s*with|update\\s*your)\\b" +
          `|${HI.send}|${HI.tell}|${HI.enter}|kar(?:iye|ein|o)\\b|कर(?:िए|ें|ो)|कॉल|क्लिक|अपडेट`
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
  const t = normalize(rawText);
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
