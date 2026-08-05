// Rule-based scam signals.
//
// These exist alongside the statistical model rather than under it. The model
// gives one opaque number; these give the user a reason. They also cover the
// social-engineering patterns that are stable across languages and rewrites —
// a gift-card request is a gift-card request however it's phrased — where a
// bag-of-words model trained on a few hundred examples is brittle.

import { normalize } from "../lib/text.js";

const CREDENTIAL_NOUN_RE =
  /\b(?:password|passcode|pin(?:\s*(?:number|code))?|otp|one[\s-]?time\s*(?:password|code|pin)|cvv|card\s*(?:number|details)|security\s*code|seed\s*phrase|recovery\s*phrase|private\s*key|aadhaar|ssn|social\s*security)\b/;

// The secret leaving your possession, *towards whoever is asking*. The
// direction is the whole signal: "send OTP to your registered mobile" is a real
// bank's own button and "send me your OTP" is a theft, and both contain "send".
// So the verb has to carry an indirect object pointing back at the sender. Bare
// verbs matched far too much — including the word "email" sitting on the login
// form of every site in the world.
const CREDENTIAL_TRANSMIT_RE =
  /\b(?:(?:send|forward|give|tell|text|whatsapp|email|message)\s+(?:it\s+)?(?:me|us|back|to\s+(?:me|us))|share\s+(?:your|the|it|with)|reply\s+(?:with|back\s+with)|revert\s+with|provide\s+(?:me|us))\b/;

// Verbs that describe typing a secret into a form. Damning in a message,
// unremarkable on the login page it describes — see the rule below.
const CREDENTIAL_ENTRY_RE = /\b(?:enter|provide|confirm|verify|submit|update)\b/;

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
    test: (t) => /\b(?:gift\s*card|itunes\s*card|steam\s*(?:card|wallet)|google\s*play\s*card|voucher\s*code|prepaid\s*card)\b/.test(t),
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
      /\b(?:upi|gpay|google\s*pay|phonepe|paytm|bhim|qr\s*code)\b/.test(t) &&
      /\b(?:collect\s*request|accept|approve|scan|enter\s*(?:your\s*)?pin|receive|refund|cashback)\b/.test(t),
  },
  {
    id: "account_suspension",
    weight: 1.5,
    why: "It claims your account is suspended, locked, or about to be closed. Manufactured account trouble is the standard hook for stealing logins.",
    test: (t) =>
      /\b(?:account|card|profile|subscription|service)\b[^.!?]{0,40}\b(?:suspend(?:ed)?|lock(?:ed)?|block(?:ed)?|disabl(?:ed)?|deactivat(?:ed)?|restrict(?:ed)?|clos(?:ed|ure)|terminat(?:ed)?|on\s*hold)\b/.test(t),
  },
  {
    id: "artificial_urgency",
    weight: 1.2,
    why: "It sets a countdown. Deadlines like this exist to stop you checking with someone before you act.",
    test: (t) =>
      /\b(?:within\s*\d+\s*(?:hour|hr|minute|min|day)|in\s*the\s*next\s*\d+\s*(?:hour|minute)|before\s*(?:midnight|today|tonight|it\s*expires)|expir(?:es|ing)\s*(?:today|soon|in)|last\s*(?:chance|warning)|final\s*(?:notice|warning|reminder)|immediately|right\s*away|act\s*now|urgent(?:ly)?|asap)\b/.test(t),
  },
  {
    id: "threat_of_consequence",
    weight: 1.7,
    why: "It threatens arrest, legal action, or a fine. Real agencies send written notices; they do not threaten you over email or chat.",
    test: (t) =>
      /\b(?:arrest(?:ed)?|legal\s*action|lawsuit|court|police|fir\b|warrant|prosecut(?:e|ion)|penalt(?:y|ies)|fine|seiz(?:e|ed|ure)|deport|jail|criminal\s*(?:case|charge))\b/.test(t),
  },
  {
    id: "prize_or_windfall",
    weight: 1.9,
    why: "It says you've won something you never entered, or money is waiting for you. Unsolicited winnings are a lure to collect your details or an upfront \"fee\".",
    test: (t) =>
      /\b(?:you(?:'ve| have)?\s*(?:been\s*)?(?:won|win|selected|chosen)|congratulations|lucky\s*winner|claim\s*your\s*(?:prize|reward|gift)|lottery|jackpot|unclaimed\s*(?:funds|money|refund)|inherit(?:ance|ed))\b/.test(t),
  },
  {
    id: "advance_fee",
    weight: 2.0,
    why: "It asks for a payment up front to release a larger sum. That larger sum does not exist.",
    test: (t) =>
      /\b(?:processing\s*fee|clearance\s*fee|customs\s*(?:fee|duty|charge)|release\s*fee|registration\s*fee|handling\s*charge|small\s*(?:fee|amount)|refundable\s*deposit)\b/.test(t),
  },
  {
    id: "impersonated_authority",
    weight: 1.4,
    why: "It claims to be from a bank, tax office, or support desk. Check by contacting them yourself using a number you already have — never one from the message.",
    test: (t) =>
      /\b(?:income\s*tax|irs\b|hmrc|customs|cyber\s*cell|trai\b|rbi\b|federal|government|microsoft\s*support|apple\s*support|tech\s*support|security\s*team|fraud\s*department)\b/.test(t),
  },
  {
    id: "secrecy_request",
    weight: 2.1,
    why: "It tells you to keep this quiet or not to contact anyone. Isolating you from a second opinion is a deliberate tactic, not a business practice.",
    test: (t) =>
      /\b(?:do\s*not\s*(?:tell|inform|discuss|share\s*this)|keep\s*(?:this|it)\s*(?:confidential|secret|between\s*us)|don'?t\s*(?:tell|call|contact)\s*(?:anyone|police|bank)|without\s*informing)\b/.test(t),
  },
  {
    id: "unexpected_attachment_or_install",
    weight: 1.6,
    why: "It wants you to install software or open an attachment to fix a problem. That software is how they take control of your device.",
    test: (t) =>
      /\b(?:anydesk|teamviewer|quick\s*support|remote\s*(?:access|desktop)|install\s*(?:this|the)\s*app|download\s*(?:the\s*)?(?:apk|attachment|file)|enable\s*(?:macros|installation\s*from\s*unknown))\b/.test(t),
  },
  {
    id: "boss_impersonation",
    weight: 2.3,
    why: "Someone claiming to be your boss or a colleague is asking for money or data from an unfamiliar address. Verify on a channel you already trust before acting.",
    test: (t) =>
      /\b(?:this\s*is\s*(?:your\s*)?(?:ceo|manager|director|boss|hr)|i(?:'m| am)\s*(?:your\s*)?(?:ceo|manager|boss)|new\s*(?:number|email)[^.!?]{0,30}\b(?:this\s*is|it'?s)\b)/.test(t) ||
      (/\b(?:ceo|manager|director|boss)\b/.test(t) && /\b(?:urgent|discreet|favou?r|right\s*now|quick\s*task)\b/.test(t)),
  },
  {
    id: "payment_detail_change",
    weight: 2.5,
    why: "It asks to redirect a payment to different bank details. This is how invoice-redirection fraud works — always confirm by phone using a number you already have.",
    test: (t) =>
      /\b(?:updated?|new|changed?|different)\s*(?:bank(?:ing)?|account|payment|remittance|wire)\s*(?:details|information|info|number)\b/.test(t) ||
      /\bchange\s*(?:the\s*)?(?:bank|payment)\s*details\b/.test(t),
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
        /\b(?:mum|mom|dad|papa|mummy|beta|bro|sis|son|daughter|uncle|aunt(?:y|ie)?|grand(?:ma|pa)|it'?s\s*me)\b/.test(t);
      if (!relationship) return false;

      // NOTE: normalize() folds digits onto letters to defeat homoglyphs, so
      // "8000" arrives as "8ooo". Never match \d in a heuristic — the amount
      // has to be recognised by the words around it.
      const wantsMoney =
        /\b(?:send|transfer|pay|paying|need|deposit|lend|credit)\b/.test(t) &&
        /\b(?:money|cash|rs|inr|rupees|upi|gpay|paytm|phonepe|amount|rent|fees?|funds?|account)\b/.test(t);
      if (!wantsMoney) return false;

      const unreachable =
        /\b(?:new|different|temp(?:orary)?|another|friend'?s|borrowed)\s*(?:number|phone|mobile|sim)\b|lost\s*my\s*(?:phone|wallet)|broke\s*my\s*(?:phone|screen)|texting\s*from\b/.test(t);
      const crisis =
        /\b(?:accident|hospital|emergency|surgery|operation|admitted|icu|stuck|stranded|detained|arrested|police\s*station|urgent(?:ly)?|tonight|right\s*(?:now|away))\b/.test(t);

      return unreachable || crisis;
    },
  },
  {
    id: "delivery_redispatch_fee",
    weight: 2.0,
    why: "It says a delivery needs money or re-confirmation before it can reach you. Couriers do not charge you to re-attempt a delivery — the fee is the scam, and the page that collects it collects your card.",
    test: (t) => {
      if (!/\b(?:deliver(?:y|ed|ies)?|dispatch|shipment|parcel|package|courier|consignment)\b/.test(t)) {
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
        /\b(?:could\s*not|couldn'?t|cannot|can'?t|failed|unsuccessful|unable\s*to|attempt(?:ed)?|on\s*hold|pending|held|suspended|incomplete|incorrect\s*address)\b|address\s*verification/.test(t);
      const action = /reschedul|re-?dispatch|re-?deliver|\bconfirm|\bverif|update\s*your\s*address/.test(t);
      const payment = /\b(?:pay|paying|payment|fees?|charges?|deposit|customs|duty)\b/.test(t);

      return [failed, action, payment].filter(Boolean).length >= 2;
    },
  },
  {
    id: "job_advance_fee",
    weight: 2.2,
    why: "It offers work but asks you to pay first — a deposit, registration, or kit charge. Real employers pay you; they never ask you to pay them to start.",
    test: (t) =>
      /\b(?:job|work\s*from\s*home|part[\s-]?time|data\s*entry|hiring|vacancy|earn|salary|income|packing|typing|recruit)\b/.test(t) &&
      /\b(?:pay|deposit|paying|charge|fee|amount|registration|security|refundable|membership|joining|advance)\b/.test(t) &&
      // No \d here on purpose: normalize() folds digits onto letters, so an
      // amount arrives as "soo" rather than "500". The charge is identified by
      // what it is called, not by the number attached to it.
      /\b(?:registration|security|refundable|membership|joining|processing|courier|kit|training|advance|one[\s-]?time)\b[^.!?]{0,20}\b(?:fee|deposit|charge|amount|payment|of)\b|\b(?:pay|deposit)\b[^.!?]{0,25}\b(?:rs|inr|registration|deposit|membership)\b/.test(t),
  },
  {
    id: "refund_callback",
    weight: 1.8,
    why: "It reports a charge you don't recognise and gives a number to call to cancel it. The number reaches the scammer, who will talk you into remote access or a transfer to \"refund\" you.",
    test: (t) =>
      /\b(?:auto[\s-]?renew(?:ed|al)?|subscription|invoice|order|debited|charged|transaction|purchase|renewal)\b/.test(t) &&
      /\b(?:call|dial|contact|helpline|toll[\s-]?free|customer\s*(?:care|support)|reach\s*us)\b/.test(t) &&
      /\b(?:cancel|refund|dispute|unauthori[sz]ed|not\s*(?:authori[sz]ed|you|recognise|recognize)|if\s*this\s*(?:was|is)\s*not|to\s*stop)\b/.test(t),
  },
  {
    id: "windfall_solicitation",
    weight: 2.2,
    why: "A stranger says they want to move a large sum of money through you, usually with a story about illness, war, or a dead relative. The story is a script, and the money does not exist.",
    test: (t) =>
      /\b(?:million|billion|crore|lakh|fortune|inheritance|estate|fund(?:s)?|sum\s*of\s*money|deposit\s*of)\b/.test(t) &&
      /\b(?:widow|terminal(?:ly)?\s*ill|dying|late\s*husband|deceased|next\s*of\s*kin|beneficiar(?:y|ies)|barrister|army\s*officer|deployed|refugee|orphan|god[\s-]?fearing|trusted\s*partner|business\s*proposal)\b/.test(t),
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
    test: (t) =>
      !/\b(?:click|tap|verify|confirm|login|log\s*in|sign\s*in|pay|send|transfer|share|download|install|call|reply\s*with|update\s*your)\b/.test(t),
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
