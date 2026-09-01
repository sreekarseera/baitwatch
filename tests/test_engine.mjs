// End-to-end tests for the detection engine, run outside Chrome.
//
// These are behavioural, not unit, tests: each case is a message a real person
// could receive and the verdict the extension must reach. False positives are
// tested as seriously as false negatives — an extension that cries wolf on
// ordinary email gets uninstalled, which protects nobody.
//
//     node tests/test_engine.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const ext = join(here, "..", "extension");

globalThis.chrome = { runtime: { getURL: (p) => join(ext, p) } };
globalThis.fetch = async (path) => ({
  ok: true,
  json: async () => JSON.parse(readFileSync(path, "utf-8")),
});

const { analyze, analyzeLocal, shouldEscalate, VERDICT, THRESHOLDS } = await import(join(ext, "engine", "engine.js"));
const { analyzeUrls, editDistance, registrableDomain } = await import(join(ext, "engine", "urls.js"));
const { analyzeHeuristics } = await import(join(ext, "engine", "heuristics.js"));
const { punycodeToUnicode } = await import(join(ext, "lib", "punycode.js"));
const { normalize } = await import(join(ext, "lib", "text.js"));
const { CONFUSABLES } = await import(join(ext, "lib", "confusables-data.js"));

let passed = 0;
const failures = [];

function check(name, condition, detail = "") {
  if (condition) passed++;
  else failures.push(`${name}${detail ? ` — ${detail}` : ""}`);
}

/* ------------------------- must be flagged as scams ------------------------ */

const SCAMS = [
  ["gift card / boss impersonation",
   "Hi, this is your CEO. I'm in a meeting and need you to buy $500 in Apple gift cards urgently. Send me the codes and don't discuss this with anyone."],
  ["OTP harvest",
   "HDFC Bank Alert: Your account will be blocked within 24 hours. Share the OTP sent to your registered number to complete verification immediately."],
  ["UPI collect-request",
   "Congratulations! Your refund of Rs 4,500 is ready. Accept the UPI collect request on your PhonePe app and enter your PIN to receive it instantly."],
  ["lookalike domain",
   "Your PayPal account has been limited. Restore access here: https://paypa1-secure.com/login"],
  ["brand in subdomain",
   "Amazon: your order could not be shipped. Update your card at http://amazon.com.delivery-update.tk/verify"],
  ["remote access / tech support",
   "Microsoft Support: your computer is infected. Install AnyDesk and call 1-800-555-0199 immediately so our technician can remove the virus."],
  ["invoice redirection",
   "Please note our bank details have changed. Send the outstanding payment to the new account number below for this month's invoice."],
  ["advance fee",
   "You have been selected to receive $50,000 from the International lottery. Pay the small processing fee of $250 to release your funds."],
  ["arrest threat",
   "Income Tax Department: You owe unpaid taxes. A warrant has been issued. Pay immediately via gift card to avoid arrest and legal action."],
  ["crypto doubling",
   "Double your Bitcoin in 24 hours! Send BTC to this wallet address now, offer expires today."],
  ["IP-address link",
   "Your Netflix subscription payment failed. Update your billing details at http://192.168.44.9/netflix/login within 12 hours."],
  ["@-trick URL",
   "Verify your Microsoft account now: https://login.microsoft.com@account-verify.xyz/session"],
  ["credential phish, generic salutation",
   "Dear Customer, we detected unusual activity. Your account has been suspended. Confirm your password and card number here: http://bit.ly/verify-acct"],
  ["prize lure, subject isn't literally \"you\"",
   "Your email was selected to receive a charity grant of 950,000 pounds from our foundation. Provide your account for disbursement."],
  ["OTP relay disguised as a rewards redemption",
   "Credit card reward points worth 9,750 expiring today. Redeem now by sharing the confirmation code you receive on SMS."],
  ["guaranteed-return investment pitch, plural verb",
   "Dear investor, our advisory group guarantees 40 percent monthly returns on crypto. Start with a small deposit and withdraw anytime."],
  // The other half of the three 2026-09-01 conversions: the same topics as the
  // LEGIT rows below, but performing the act each rule is named for. The
  // investment pitch never uses the word "guarantee", so it exercises the
  // promised-yield branch that replaced the ungated conjunction.
  ["investment pitch promising a fixed daily return, no \"guarantee\" in it",
   "Join our trading group and earn a fixed daily profit of 3% on your capital. Minimum deposit to start is 10,000 rupees — send it to the UPI ID below and your account is activated today."],
  ["support-desk impersonation naming no company agency",
   "Hello, this is the security team. We are contacting you about unusual sign-in attempts. Reply with the verification code we just sent so we can lock the intruder out."],
  ["debt threat aimed at the reader",
   "FINAL NOTICE. Your outstanding balance remains unpaid. If you do not settle today, legal action will be initiated and a warrant issued against you. Pay here: secure-settle.co/pay"],
  // The other half of the no-ask cap (see engine.js). Each of these asks for
  // something, carries no URL, and fires only rules below the 2.4 conclusive
  // bar — so each one is convicted solely by ACTION_REQUEST_RE seeing the ask.
  // A verb dropped from that list turns any of them silently safe, which is the
  // failure mode the cap makes expensive. Every one of these is a row from
  // curated.csv or curated-hinglish.csv that the pre-audit verb list could not
  // see the ask in.
  ["Hinglish KYC threat — the ask is the imperative \"kijiye\", not the word \"update\"",
   "Aapka KYC expire ho gaya hai. Turant update kijiye warna account band ho jayega."],
  ["Hinglish customs fee — \"bharkar\" and \"karwaiye\", neither an English verb",
   "Aapka parcel customs me ruka hua hai. Clearance fee bharkar release karwaiye."],
  ["Devanagari remote-access lure — the ask is \"शेयर कीजिए\"",
   "आपके प्रिंटर ड्राइवर में गड़बड़ी की शिकायत मिली है HP सपोर्ट को, फ्री रिपेयर के लिए AnyDesk कोड शेयर कीजिए हमारे तकनीशियन के साथ।"],
  ["Devanagari SIM-deactivation threat — the ask is the IVR \"9 दबाएं\"",
   "यह TRAI से सूचना है, आपके नाम पर 9 सिम कार्ड एक्टिव हैं जो नियम विरुद्ध है, 2 घंटे में नंबर डिएक्टिवेट हो जाएगा, e-KYC के लिए 9 दबाएं।"],
  ["parcel redispatch — the whole ask is \"Reschedule\", which \\breschedul\\b can never match",
   "Amazon: Your package cannot be delivered. Reschedule here."],
  ["419 letter — the ask is \"respond with\", not the \"reply with\" the list knew",
   "I am a widow with terminal illness wishing to donate my late husband's fortune to you. Kindly respond with your details."],
  ["fake ISP — the ask is \"give us\", gated on the indirect object",
   "We are from your internet provider. Your router is compromised. Give us remote access to fix it or your connection will be disconnected."],
  ["job advance fee — the ask is \"paying\", which \\bpay\\b cannot match",
   "Earn from YouTube likes! Get paid per video. Join by paying a one time membership of 250 only."],
  // The cap's escape hatch, and the invariant underneath it. This names no
  // action at all ("double" is not an ask) and carries no link, so the cap
  // would hold it under 35 — except crypto_transfer is 2.4, at or above
  // CONCLUSIVE_AT, and a conclusive rule is exempt. It is also a single rule
  // convicting alone with nothing corroborating it, which must keep working:
  // 62% of the scams this tool catches rest on one rule.
  ["conclusive rule alone, with no ask and no link, is exempt from the cap",
   "Double your Bitcoin in 24 hours. Wallet address below, offer expires today."],
];

for (const [name, text] of SCAMS) {
  const r = await analyzeLocal(text);
  check(
    `scam: ${name}`,
    r.verdict !== VERDICT.SAFE,
    `scored ${r.score}/100, verdict "${r.verdict}", ${r.reasons.length} reason(s)`
  );
  check(`scam explains itself: ${name}`, r.reasons.length > 0, "no human-readable reason produced");
}

/* ---------------------- must NOT be flagged (false positives) --------------- */

const LEGIT = [
  ["meeting reschedule",
   "Hi Priya, can we move tomorrow's sync to 2:30 PM? I have a conflict at 1. Let me know if that works."],
  ["shipping notification",
   "Your order from Target has shipped and should arrive by Thursday. Track it in your account."],
  ["code review",
   "Could you review my pull request when you get a chance? It's the refactor we discussed on Monday."],
  ["restaurant confirmation",
   "Your reservation at Bella Italia for 7 PM on Friday is confirmed. We look forward to seeing you."],
  ["newsletter",
   "Here's this week's engineering newsletter with updates from the team, including the migration retro."],
  ["urgent but legitimate",
   "As discussed on our call, the deck for the board meeting is due EOD — attached is the latest draft for your review."],
  ["personal message",
   "Mom asked if you're coming home for dinner Sunday. Let her know either way, she's planning the shopping."],
  ["genuine bank domain",
   "Your monthly statement is now available. Sign in at https://www.chase.com to view it."],
  ["security article",
   "Reminder from IT: we will never ask for your password by email. If you receive such a request, report it to the helpdesk."],
  ["appointment",
   "Reminder: your dentist appointment is on Wednesday at 10 AM. Reply STOP to opt out of reminders."],
  // Real false positive, reported live: crypto_transfer used to match "crypto"
  // and "invest"/"deposit" anywhere in the message with no proximity check, so
  // any crypto brokerage's routine legal footer tripped it even with no ask
  // anywhere in the text. See docs/PROGRESS.md, 2026-08-16.
  ["crypto brokerage legal footer, no ask anywhere in the message",
   "Account Verification. Hey there — thanks for signing up to Alpaca's Trading API! To start trading with this account, please confirm your email. Confirm Email. Securities are offered through Alpaca Securities LLC. Crypto is offered through Alpaca Crypto LLC. Please carefully consider your investment objectives before you invest or deposit funds."],
  // Also reported live: the model itself had never seen a legitimate example
  // of "verify your email" — every occurrence of that phrase in the training
  // ham rows was zero before 2026-08-16. Fixed with real training-data
  // additions, not a rule; this is the regression test for that fix.
  ["new-account verification email, no threat or urgency",
   "Verify your email address. Please verify your email address to finish setting up your new Bitwarden account. Verify Email Address. If you did not request this email, you can safely ignore it. This link will expire in 24 hours."],
  // Real false positive, reported live against the actual page (whole-page
  // scan, not a message): docs.alpaca.markets/us/docs/about-alpaca scored
  // 74/dangerous on "crypto trading" (paragraph 1) and "Invest Like the
  // Best" — a podcast title, inside an unrelated investor's bio three
  // paragraphs later — combining under the pre-fix crypto_transfer rule.
  // Real page text, fetched live rather than reconstructed.
  ["long informational page mentioning crypto and \"invest\" in unrelated places",
   "About Alpaca. History & Founders. Alpaca is a technology company headquartered in Silicon Valley that builds a simple and modern API for stock and crypto trading. Our Brokerage services are provided by Alpaca Securities LLC, a member of FINRA/SIPC. Our investors include a group of well-capitalized investors including Portage Ventures, Spark Capital, Tribe Capital, Social Leverage, Horizons Ventures, Elderidge, and Y Combinator as well as highly experienced industry angel investors such as Joshua S. Levine (former CTO/COO of ETRADE), Nate Rodland (former COO of Robinhood and GP of Elefund), Patrick O'Shaughnessy (\"Invest Like the Best\" podcast host and Partner of Positive Sum), Jacqueline Reses (former Executive Chairman of Square Financial Services). We currently support stocks, ETFs listed in the US public exchanges (NMS stocks), Options trading, and cryptocurrencies."],
  // Real false positive, reported live against the LinkedIn feed: bare
  // "congratulations" was an alternative in prize_or_windfall with no gate, so
  // an ordinary well-wish scored 51/100 and warned. See docs/PROGRESS.md,
  // 2026-09-01.
  ["ordinary congratulation with no winnings anywhere in it",
   "Global Dreams. Global Destinations. Congratulations to Rajshree S N on securing admission to Singapore Institute of Management (University of London)."],
  ["congratulation on an award, which names a prize but is not one you won",
   "Congratulations to the whole team on being shortlisted for the design award — the ceremony is on the 14th and I hope everyone can make it."],
  ["hindi congratulation on an exam result",
   "बधाई हो! आपने बोर्ड परीक्षा में बहुत अच्छे अंक प्राप्त किए हैं। आपके उज्ज्वल भविष्य की शुभकामनाएं।"],
  // The three topic-shaped rules converted on 2026-09-01. Each of these
  // discusses the rule's topic at length and asks the reader for nothing, which
  // is the distinction the old bare alternations could not draw — they warned
  // on 57 of the 1,834 legitimate corpus rows between them. See
  // docs/PROGRESS.md.
  //
  // investment_scam used to be (invest|stock|scheme|ipo) anywhere AND
  // (money|profit|return|scheme) anywhere, ungated, so any financial writing
  // tripped it. Now it wants a *promised* yield next to the instrument.
  ["financial newsletter discussing stocks and returns with nothing on offer",
   "Market Notes, week 14. The fund's portfolio returned 4.1% over the quarter, trailing the index by roughly 60 basis points. We continue to invest in mid-cap industrials, and the IPO window looks likely to reopen in the second half. As always, past performance is no guide to future returns and every investment carries risk. Reply to this note if you would like the full holdings table."],
  // threat_of_consequence used to be a bare alternation of
  // arrest|court|police|fine|jail, which is the ordinary vocabulary of news.
  // Now the consequence has to be aimed at the reader.
  ["news report of an arrest, addressed to nobody",
   "Six arrested for attacking Palio jockey. Police in Siena said the six men, all aged between 19 and 34, will appear in court next month on charges of assault. A lawyer for the accused said his clients deny any wrongdoing, and a fine of up to 3,000 euros is possible if they are convicted."],
  ["mailing-list thread about legal action someone else is taking",
   "Re: Defending Unliked Speech. Robert writes: here's hoping the tradition perseveres for the novelist currently on trial in Paris. The suit was filed by four Islamic organisations and a human rights group, and the prosecution has asked for a suspended sentence rather than jail."],
  // impersonated_authority used to include a bare federal|government, so any
  // political thread tripped it. Now the message has to claim to *be* the
  // authority.
  ["political mailing-list thread about government policy",
   "Re: the broadband bill. The government's own regulator admits the rollout targets were never realistic, and the federal subsidy programme has been reannounced three times. Worth reading the committee transcript before Thursday's call — I'll circulate the link."],
  // The no-ask cap (see engine.js). Each of these is a topic-shaped rule
  // faithfully reporting its topic in text that asks the reader for nothing and
  // carries no link — the class docs/PROGRESS.md 2026-09-01 identifies as the
  // source of the recurring false positives. Scores before the cap are in the
  // labels; each one is a real corpus row or a close paraphrase of one.
  ["mailing-list thread about arrests — threat_of_consequence reporting a topic (was 30)",
   "Six arrested for attacking Palio jockey. The court in Siena heard that police detained the group after the race; a fine of 2,000 euros was imposed on the stable. Thread continues from last week's digest."],
  ["think-tank press release on market regulation — was 67, \"dangerous\"",
   "GOVERNMENT REGULATION IS KILLING THE STOCK MARKET. Press release from the Ayn Rand Institute, Irvine CA. Federal securities rules have destroyed investor confidence and depressed returns across the market, argues a new commentary."],
  ["mailing-list post that happens to say \"security team\" and \"government\" — was 43",
   "[Spambayes] Deployment. FYI, I'll never trust such a scheme: I have no idea what the security team would say about it, and the government would probably have opinions too. Anyway, that was my two cents."],
  ["hindi crime report — a filed case is a fact being reported, not a threat made to you (was 49)",
   "पुलिस ने मामला दर्ज किया है और जांच जारी है। साइबर सेल के अधिकारियों ने बताया कि यह गिरोह पिछले साल से सक्रिय था।"],
];

for (const [name, text] of LEGIT) {
  const r = await analyzeLocal(text);
  check(
    `legit: ${name}`,
    r.verdict === VERDICT.SAFE,
    `scored ${r.score}/100, verdict "${r.verdict}"${r.reasons.length ? `, fired: ${r.reasons.map((x) => x.id).join(", ")}` : ""}`
  );
}

/* -------------------------------- punycode --------------------------------- */
// Vectors from RFC 3492 section 7.1, plus the malformed input a hostile
// hostname can carry. A hand-written decoder of a published standard is
// exactly the kind of code that should be pinned to the standard's own tests.

for (const [encoded, expected] of [
  ["xn--maana-pta", "mañana"],
  ["xn--bcher-kva", "bücher"],
  ["xn--egbpdaj6bu4bxfgehfvwxn", "ليهمابتكلموشعربي؟"],
  ["xn--3e0b707e", "한국"],
  ["xn--80akhbyknj4f", "испытание"],
  ["xn--j6w193g", "香港"],
]) {
  check(
    `punycode decodes ${encoded}`,
    punycodeToUnicode(encoded) === expected,
    `got ${JSON.stringify(punycodeToUnicode(encoded))}`
  );
}

for (const malformed of ["xn--", "xn--!!!", "xn---", "xn--a-#####", "example"]) {
  check(
    `malformed punycode is passed through, not thrown on (${malformed})`,
    punycodeToUnicode(malformed) === malformed,
    `got ${JSON.stringify(punycodeToUnicode(malformed))}`
  );
}

check(
  "only punycode labels are touched",
  punycodeToUnicode("mixed.xn--bcher-kva.co.uk") === "mixed.bücher.co.uk",
  punycodeToUnicode("mixed.xn--bcher-kva.co.uk")
);

/* ------------------------------ URL analysis ------------------------------- */

check("editDistance basic", editDistance("paypal", "paypa1") === 1);
check("editDistance early bail", editDistance("a", "abcdefghij", 2) > 2);
check("registrableDomain simple", registrableDomain("mail.google.com") === "google.com");
check("registrableDomain co.uk", registrableDomain("shop.example.co.uk") === "example.co.uk");
check("registrableDomain bare", registrableDomain("example.com") === "example.com");

// Public suffix handling. The private section of the list is the part that
// matters most here: a page on free hosting must not share a registrable
// domain with the platform or with anyone else's page on it, or every
// github.io site — hostile and legitimate alike — looks like one domain.
check("psl separates free-hosting subdomains",
  registrableDomain("evil.github.io") === "evil.github.io");
check("psl free-hosting siblings stay distinct",
  registrableDomain("evil.github.io") !== registrableDomain("legit.github.io"));
check("psl vercel", registrableDomain("phish.vercel.app") === "phish.vercel.app");
check("psl pages.dev", registrableDomain("scam.pages.dev") === "scam.pages.dev");
check("psl deep private suffix",
  registrableDomain("a.b.herokuapp.com") === "b.herokuapp.com");
check("psl multi-part icann", registrableDomain("a.b.c.co.uk") === "c.co.uk");
check("psl indian bank suffix", registrableDomain("foo.sbi.co.in") === "sbi.co.in");
check("psl host that is itself a suffix",
  registrableDomain("github.io") === "github.io");
check("psl unknown tld falls back to last two labels",
  registrableDomain("a.b.unknown-tld-xyz") === "b.unknown-tld-xyz");
check("psl single label", registrableDomain("localhost") === "localhost");

const shortener = analyzeUrls("click http://bit.ly/abc123 now");
check("detects shortener", shortener.signals.some((s) => s.id === "url_shortener"));

const genuine = analyzeUrls("sign in at https://www.paypal.com/signin");
check(
  "does not flag genuine brand domain",
  !genuine.signals.some((s) => s.id === "lookalike_domain"),
  `fired: ${genuine.signals.map((s) => s.id).join(", ") || "none"}`
);

const genuineSub = analyzeUrls("go to https://accounts.google.com/signin");
check(
  "does not flag genuine brand subdomain",
  !genuineSub.signals.some((s) => s.id === "lookalike_domain"),
  `fired: ${genuineSub.signals.map((s) => s.id).join(", ") || "none"}`
);

// A punycode PayPal spoof. This used to be reported as "a punycode domain",
// which told the user nothing; decoding it first means the lookalike layer now
// recognises the brand being imitated and says so.
const punycode = analyzeUrls("visit https://xn--pypal-4ve.com/login");
check(
  "punycode spoof is decoded and attributed to the brand",
  punycode.signals.some((s) => s.id === "lookalike_domain"),
  `fired: ${punycode.signals.map((s) => s.id).join(", ") || "none"}`
);

const noUrls = analyzeUrls("there is no link in this message at all");
check("no false URLs in plain text", noUrls.urls.length === 0, `found: ${noUrls.urls.join(", ")}`);

const emailNotUrl = analyzeUrls("write to support@example.com for help");
check(
  "email address is not treated as a URL",
  noUrls.urls.length === 0 && !emailNotUrl.urls.includes("support@example.com"),
  `found: ${emailNotUrl.urls.join(", ")}`
);

/* ---------------------------- whole-page scanning -------------------------- */
// A credential-harvest page shows innocuous text and hides the hostile domain
// in an href. These check that link targets and the page's own address are
// judged, not just what the user can read.

const innocuousText = "Sign in to continue to your account. Email. Password. Remember me.";

const textOnly = await analyzeLocal(innocuousText);
check(
  "fake login page looks harmless from visible text alone",
  textOnly.verdict === VERDICT.SAFE,
  `scored ${textOnly.score} — this is the baseline the href check must beat`
);

const withHref = await analyzeLocal(innocuousText, {
  extraUrls: ["https://paypa1-secure.com/login", "https://paypa1-secure.com/submit"],
});
check(
  "same page is caught once link targets are examined",
  withHref.verdict !== VERDICT.SAFE,
  `scored ${withHref.score}, reasons: ${withHref.reasons.map((r) => r.id).join(", ") || "none"}`
);

const pageAddress = await analyzeLocal("Verify your account to continue.", {
  extraUrls: ["https://amazon.com.account-verify.tk/signin"],
});
check(
  "the page's own address is judged",
  pageAddress.reasons.some((r) => r.id === "lookalike_domain"),
  `reasons: ${pageAddress.reasons.map((r) => r.id).join(", ") || "none"}`
);

const genuinePage = await analyzeLocal(
  "Your monthly statement is ready. Sign in to view it.",
  { extraUrls: ["https://www.chase.com/login", "https://www.chase.com/help"] }
);
check(
  "a genuine bank page stays clean under whole-page scan",
  genuinePage.verdict === VERDICT.SAFE,
  `scored ${genuinePage.score}, fired: ${genuinePage.reasons.map((r) => r.id).join(", ") || "none"}`
);

const manyLinks = await analyzeLocal("Ordinary blog post about cooking.", {
  extraUrls: Array.from({ length: 150 }, (_, i) => `https://example.com/post/${i}`),
});
check(
  "a link-heavy ordinary page is not flagged",
  manyLinks.verdict === VERDICT.SAFE,
  `scored ${manyLinks.score}`
);

// Homoglyph domains that fold to the brand's domain *exactly*. These are the
// most clear-cut impersonations there are, and were the ones the edit-distance
// branch skipped: after folding it saw two identical labels and moved on.
for (const [name, url] of [
  ["leetspeak digit", "http://paypa1.com/login"],
  ["rn read as m", "http://arnazon.com/order"],
]) {
  const folded = analyzeUrls("", [url]);
  check(
    `homoglyph domain is attributed to the brand (${name})`,
    folded.signals.some((s) => s.id === "lookalike_domain"),
    `${url} fired: ${folded.signals.map((s) => s.id).join(", ") || "nothing"}`
  );
}

// Non-Latin homoglyphs arrive already punycode-encoded — `new URL()` hands
// back "xn--aypal-uye.com" — so the folding has to happen on the far side of a
// decode or it is folding an ASCII envelope.
for (const [name, url, brand] of [
  ["cyrillic paypal", "http://рaypal.com/login", "PayPal"],
  ["all-cyrillic apple", "http://аррӏе.com/", "Apple"],
  ["cyrillic google", "http://gооgle.com/", "Google"],
  ["cyrillic netflix", "http://nеtflix.com/", "Netflix"],
]) {
  const idn = analyzeUrls("", [url]);
  const signal = idn.signals.find((s) => s.id === "lookalike_domain");
  check(
    `IDN homoglyph is decoded and attributed (${name})`,
    signal?.brand === brand,
    `fired: ${idn.signals.map((s) => s.id).join(", ") || "nothing"}`
  );
}

// The warning has to lead with what the user sees, not the encoded form —
// telling someone "xn--aypal-uye.com" imitates PayPal explains nothing.
const shown = analyzeUrls("", ["http://рaypal.com/login"]).signals.find(
  (s) => s.id === "lookalike_domain"
);
check(
  "the warning shows the domain as it renders, and the real address",
  shown.detail.includes("рaypal.com") && shown.detail.includes("xn--aypal-uye.com"),
  shown.detail
);

// Mixing alphabets inside one label is the attack. A domain written wholly in
// another alphabet is just a domain in that language — flagging those made
// every legitimate German, Russian, Chinese and Indian address suspicious.
for (const [name, url] of [
  ["german", "https://münchen.de/"],
  ["han", "https://香港.com/"],
  ["cyrillic tld", "https://испытание.рф/"],
  ["devanagari", "https://भारत.in/"],
]) {
  const idn = analyzeUrls("", [url]);
  check(
    `a legitimate internationalized domain is not alarming (${name})`,
    idn.score < 1.0 && !idn.signals.some((s) => s.id === "mixed_script_host"),
    `scored ${idn.score}, fired: ${idn.signals.map((s) => s.id).join(", ") || "nothing"}`
  );
}

const mixedScript = analyzeUrls("", ["https://bаnking-secure.com/"]);
check(
  "a mixed-alphabet domain is flagged even with no brand to match",
  mixedScript.signals.some((s) => s.id === "mixed_script_host"),
  `fired: ${mixedScript.signals.map((s) => s.id).join(", ") || "nothing"}`
);

const realDomains = analyzeUrls("", [
  "https://www.paypal.com/signin",
  "https://www.amazon.in/orders",
  "https://modern-kitchens.com/learn",
]);
check(
  "folding does not misfire on real domains",
  !realDomains.signals.some((s) => s.id === "lookalike_domain"),
  `fired: ${realDomains.signals.map((s) => s.id).join(", ") || "nothing"}`
);

/* ------------------------- full Unicode confusables ------------------------ */
// The fold table used to be nine Cyrillic letters and ten Greek ones, picked by
// hand, and every domain below walked straight past it — the attacker only had
// to reach one letter further down the alphabet. The table is now derived from
// Unicode's own confusables data (tools/build_confusables.py).
//
// Each of these lands on the brand's skeleton *exactly*, which is the strongest
// branch of the lookalike check. The old table did not reach them even by edit
// distance: dropping the letter it could not read left "ggle", "atsapp" and
// "utub", all two or more edits away from the brand.
for (const [name, url, brand] of [
  ["greek sigma read as o", "http://gσσgle.com/", "Google"],
  ["cyrillic omega and shha", "http://ѡһatsapp.com/", "Facebook"],
  ["greek, cyrillic and latin in one label", "http://γσutubҽ.com/", "Google"],
  ["armenian", "http://ոetflix.com/", "Netflix"],
  ["coptic", "http://ⲣaypal.com/", "PayPal"],
  ["cherokee", "http://ꮯhase.com/", "Chase"],
]) {
  const folded = analyzeUrls("", [url]);
  const signal = folded.signals.find((s) => s.id === "lookalike_domain");
  check(
    `a confusable outside the old hand-picked table is caught (${name})`,
    signal?.brand === brand,
    `${url} fired: ${folded.signals.map((s) => s.id).join(", ") || "nothing"}`
  );
}

// Caught as an exact homoglyph, not as a near-miss typo. The distinction is
// what the user is told: the warning has to say the address is built from
// characters chosen to read as the brand, and show both spellings.
const foldedDetail = analyzeUrls("", ["http://ѡһatsapp.com/"]).signals.find(
  (s) => s.id === "lookalike_domain"
);
check(
  "the widened fold still reports the domain as it renders, and the real address",
  foldedDetail.detail.includes("ѡһatsapp.com") &&
    foldedDetail.detail.includes("xn--") &&
    foldedDetail.detail.includes("whatsapp.com"),
  foldedDetail.detail
);

// These matter more than the six cases above. Folding whole scripts toward
// Latin would recreate the failure this project already shipped once — treating
// all punycode as suspicious flagged every legitimate German, Russian, Chinese
// and Indian address — only from a new direction, by making an ordinary word in
// another alphabet skeleton onto a brand. A domain written wholly in its own
// script has to stay unremarkable however many of its letters have acquired a
// Latin reading.
for (const [name, url] of [
  ["greek", "https://παράδειγμα.gr/"],
  ["russian", "https://правительство.рф/"],
  ["russian bank", "https://сбербанк.рф/"],
  ["armenian", "https://օրինակ.հայ/"],
  ["arabic", "https://السعودية.sa/"],
  ["thai", "https://กรุงเทพ.th/"],
  ["chinese", "https://中国政府.cn/"],
  ["german", "https://zürich.ch/"],
  ["danish", "https://århus.dk/"],
]) {
  const idn = analyzeUrls("", [url]);
  check(
    `a legitimate internationalized domain is not read as a brand (${name})`,
    !idn.signals.some((s) => s.id === "lookalike_domain") && idn.score < 1.0,
    `scored ${idn.score}, fired: ${idn.signals.map((s) => s.id).join(", ") || "nothing"}`
  );
}

// The same question asked of message text rather than domains: ordinary
// correspondence in another alphabet passes through normalize() before every
// heuristic sees it, so a fold that turned it into plausible English would
// warn the wrong people about the wrong thing.
for (const [name, message] of [
  ["russian", "Здравствуйте! Напоминаю, что собрание перенесено на среду в 14:00. Пожалуйста, подтвердите участие."],
  ["greek", "Καλημέρα, το ραντεβού μας μετατέθηκε για την Πέμπτη στις έντεκα. Πες μου αν σε βολεύει."],
  ["armenian", "Բարև, վաղվա հանդիպումը տեղափոխվել է ժամը երկուսին։ Խնդրում եմ հաստատել։"],
  ["chinese", "你好，明天的会议改到下午三点，请确认你是否方便参加。"],
  ["hindi", "नमस्ते, कल की मीटिंग दो बजे कर सकते हैं क्या? मुझे एक बजे दूसरा काम है।"],
]) {
  const ordinary = await analyzeLocal(message);
  check(
    `ordinary ${name} correspondence is not flagged`,
    ordinary.verdict === VERDICT.SAFE,
    `scored ${ordinary.score}, fired: ${ordinary.reasons.map((r) => r.id).join(", ") || "nothing"}`
  );
}

// Devanagari is excluded from the table on purpose, and this is why: the Hindi
// and Hinglish rules in heuristics.js match it literally, against normalize()'d
// text. A fold would switch a whole language's rules off silently.
const devanagari = "आपका खाता बंद हो जाएगा, तुरंत ओटीपी भेजें";
check(
  "normalize() leaves Devanagari exactly as it was",
  normalize(devanagari) === devanagari,
  `became ${JSON.stringify(normalize(devanagari))}`
);

// The contract the rest of the engine is written against, stated where a
// regeneration of the table would break it. Both halves are load-bearing: the
// first is how "acc0unt" reaches a keyword rule, and the second is why no
// heuristic may ever match `\d` (docs/PROGRESS.md says the same).
check(
  "leetspeak digits still fold onto letters",
  normalize("Sh4re your 0TP c0de") === "share your otp code",
  JSON.stringify(normalize("Sh4re your 0TP c0de"))
);
check(
  "which is why a rule can never match a digit",
  normalize("Pay Rs 8000 by 24 March") === "pay rs 8ooo by 2a march",
  JSON.stringify(normalize("Pay Rs 8000 by 24 March"))
);

// Ordinary Latin text has to survive untouched. A table that folded Latin into
// anything else would be worse than no table at all — every keyword rule reads
// the output of this function.
const pangram = "the quick brown fox jumps over the lazy dog";
check(
  "plain Latin text passes through the fold unchanged",
  normalize(pangram) === pangram,
  JSON.stringify(normalize(pangram))
);

// Structural guards on the generated table itself, so a regeneration that
// widens it too far fails here rather than in the field.
check(
  "every mapping folds a non-ASCII character onto a single ASCII letter",
  [...CONFUSABLES].every(([from, to]) => from.codePointAt(0) > 127 && /^[A-Za-z]$/.test(to)),
  [...CONFUSABLES]
    .filter(([from, to]) => from.codePointAt(0) <= 127 || !/^[A-Za-z]$/.test(to))
    .map(([from, to]) => `${from}->${to}`)
    .join(", ")
);
const PROTECTED_SCRIPTS =
  /[\p{Script=Devanagari}\p{Script=Arabic}\p{Script=Hebrew}\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}\p{Script=Bengali}\p{Script=Tamil}\p{Script=Telugu}]/u;
check(
  "no script the engine still has to read was folded",
  ![...CONFUSABLES.keys()].some((ch) => PROTECTED_SCRIPTS.test(ch)),
  [...CONFUSABLES.keys()].filter((ch) => PROTECTED_SCRIPTS.test(ch)).join(", ")
);

const dedup = analyzeUrls("see http://bit.ly/a", ["http://bit.ly/a", "http://bit.ly/b"]);
check(
  "shortener signal is not multiplied by repeated links",
  dedup.signals.filter((s) => s.id === "url_shortener").length === 1,
  `${dedup.signals.filter((s) => s.id === "url_shortener").length} shortener signals`
);

/* --------------------------- brand impersonation --------------------------- */
// The domain makes no attempt to look like the brand; the *page* does. Every
// rule here is conjunctive, so the negatives below matter more than the
// positives — this layer scores high enough to move a verdict on its own.

function pageScan(text, page) {
  return analyzeLocal(text, { extraUrls: [page.url], page });
}

const fakeLogin = await pageScan("Log in to your PayPal account to continue. Email. Password.", {
  url: "https://secure-portal-9f2.com/login",
  title: "PayPal - Log In",
  credentialFields: ["password"],
  formTargets: ["https://secure-portal-9f2.com/submit"],
});
check(
  "page claiming a brand it isn't served by is flagged",
  fakeLogin.reasons.some((r) => r.id === "brand_impersonation"),
  `scored ${fakeLogin.score}, fired: ${fakeLogin.reasons.map((r) => r.id).join(", ") || "none"}`
);

const otpHarvest = await pageScan("Enter the code we sent to your phone to restore access.", {
  url: "https://verify-portal-x.com/otp",
  title: "HDFC Bank NetBanking",
  credentialFields: ["otp"],
  formTargets: [],
});
check(
  "an OTP-only field counts as a credential request",
  otpHarvest.reasons.some((r) => r.id === "brand_impersonation"),
  `fired: ${otpHarvest.reasons.map((r) => r.id).join(", ") || "none"}`
);

const offsitePost = await pageScan("Sign in to Netflix to continue watching. Password.", {
  url: "https://cdn-media-host.com/account",
  title: "Netflix",
  credentialFields: ["password"],
  formTargets: ["https://collector-8811.com/save"],
});
check(
  "a form posting credentials to a third site corroborates",
  offsitePost.reasons.some((r) => r.id === "offsite_credential_post"),
  `fired: ${offsitePost.reasons.map((r) => r.id).join(", ") || "none"}`
);

const realBrand = await pageScan("Log in to your PayPal account to continue. Email. Password.", {
  url: "https://www.paypal.com/signin",
  title: "PayPal - Log In",
  credentialFields: ["password"],
  formTargets: ["https://www.paypal.com/auth"],
});
check(
  "the brand's own login page is not impersonation",
  realBrand.verdict === VERDICT.SAFE && !realBrand.reasons.some((r) => r.id === "brand_impersonation"),
  `scored ${realBrand.score}, fired: ${realBrand.reasons.map((r) => r.id).join(", ") || "none"}`
);

const brandSubdomain = await pageScan("Sign in. Password.", {
  url: "https://signin.icicibank.com/login",
  title: "ICICI Bank Internet Banking",
  credentialFields: ["password"],
  formTargets: [],
});
check(
  "a subdomain of the real brand is not impersonation",
  !brandSubdomain.reasons.some((r) => r.id === "brand_impersonation"),
  `fired: ${brandSubdomain.reasons.map((r) => r.id).join(", ") || "none"}`
);

const newsArticle = await pageScan(
  "Apple announced the new iPhone today at an event in Cupertino. Subscribers can comment below.",
  {
    url: "https://theverge.com/2026/apple-iphone",
    title: "Apple announces the new iPhone - The Verge",
    credentialFields: ["password"],
    formTargets: [],
  }
);
check(
  "an article about a brand, with a login box, is not impersonation",
  newsArticle.verdict === VERDICT.SAFE,
  `scored ${newsArticle.score}, fired: ${newsArticle.reasons.map((r) => r.id).join(", ") || "none"}`
);

const ssoButton = await pageScan(
  "Welcome back to Notely. Sign in with Google, or continue with your Apple ID. Password.",
  {
    url: "https://notely-app.com/login",
    title: "Sign in - Notely",
    credentialFields: ["password"],
    formTargets: [],
  }
);
check(
  "a third-party SSO button is not a claim to be that brand",
  !ssoButton.reasons.some((r) => r.id === "brand_impersonation"),
  `fired: ${ssoButton.reasons.map((r) => r.id).join(", ") || "none"}`
);

const noCredentials = await pageScan("Compare Netflix, Amazon and Apple TV subscription prices.", {
  url: "https://streaming-deals.com/compare",
  title: "Netflix vs Amazon Prime - which is cheaper?",
  credentialFields: [],
  formTargets: [],
});
check(
  "naming brands without asking for credentials is not impersonation",
  noCredentials.verdict === VERDICT.SAFE,
  `scored ${noCredentials.score}, fired: ${noCredentials.reasons.map((r) => r.id).join(", ") || "none"}`
);

const footerMention = await pageScan(
  `${"Read our latest recipes and cooking guides. ".repeat(20)} We accept PayPal.`,
  {
    url: "https://recipes-daily.com/account",
    title: "Recipes Daily",
    credentialFields: ["password"],
    formTargets: [],
  }
);
check(
  "a brand named far down the page is not a claim of identity",
  !footerMention.reasons.some((r) => r.id === "brand_impersonation"),
  `fired: ${footerMention.reasons.map((r) => r.id).join(", ") || "none"}`
);

const lookalikeAndClaim = await pageScan("Log in to your PayPal account. Password.", {
  url: "https://paypa1.com/login",
  title: "PayPal",
  credentialFields: ["password"],
  formTargets: [],
});
check(
  "a lookalike domain is not also billed as impersonation",
  lookalikeAndClaim.reasons.some((r) => r.id === "lookalike_domain") &&
    !lookalikeAndClaim.reasons.some((r) => r.id === "brand_impersonation"),
  `fired: ${lookalikeAndClaim.reasons.map((r) => r.id).join(", ") || "none"}`
);

// Standalone structural harvest signal: PROTECTED_BRANDS only covers brands
// common enough to hand-maintain. A credential-harvest page impersonating a
// brand that isn't on that list — a regional bank nobody's added — used to
// get no signal at all from this layer, however suspicious its structure.
// This fixture is thin, asks for two secrets at once, and posts off-site to
// a domain that is neither the page's own nor a recognized auth provider.
const brandNotListed = await pageScan(
  "Verify your Meridian Savings Bank account to continue. Password. OTP.",
  {
    url: "https://meridian-secure-login.com/verify",
    title: "Meridian Savings Bank — Secure Login",
    credentialFields: ["password", "otp"],
    formTargets: ["https://harvest-collect-9f2.ru/save"],
  }
);
check(
  "a credential harvest impersonating a brand not on PROTECTED_BRANDS still fires standalone",
  brandNotListed.reasons.some((r) => r.id === "offsite_credential_harvest"),
  `scored ${brandNotListed.score}, fired: ${brandNotListed.reasons.map((r) => r.id).join(", ") || "none"}`
);

// The discipline MODEL_MAX_PULL_PAGE holds the model layer to — able to raise
// a flag on its own, never able to convict on its own — applies here too.
// Isolate the new rule from everything else that a realistic phishing page
// also trips (its own URL usually matches credential_path in urls.js, and
// the model reads the pretext language) by using a URL path that avoids
// that regex and wording plain enough not to move the model much. What's
// left on the board is the standalone signal alone, and it must stay under
// DANGEROUS_AT.
const isolatedSignal = await pageScan("Sign in. Password. OTP.", {
  url: "https://portal-9182.com/index",
  title: "Member Portal",
  credentialFields: ["password", "otp"],
  formTargets: ["https://drop-collect-31.info/save"],
});
check(
  "the standalone signal, with nothing else tripped, cannot push a page into 'dangerous'",
  isolatedSignal.reasons.every((r) => r.id === "offsite_credential_harvest") &&
    isolatedSignal.score < THRESHOLDS.DANGEROUS_AT,
  `scored ${isolatedSignal.score}, fired: ${isolatedSignal.reasons.map((r) => r.id).join(", ") || "none"}`
);

// False-positive guard #1: a real hosted-auth provider. Off-site POST is
// exactly how Auth0/Okta/"Sign in with Google" work for sites that have
// nothing to do with the provider — this must not be indistinguishable from
// a harvest just because the destination isn't the page's own domain.
const hostedAuthFlow = await pageScan("Sign in to TaskFlow to continue to your workspace. Password.", {
  url: "https://taskflow-app.com/login",
  title: "Sign in - TaskFlow",
  credentialFields: ["password"],
  formTargets: ["https://taskflow.auth0.com/usernamepassword/login"],
});
check(
  "a real hosted-auth provider (Auth0) receiving an off-site post is not flagged",
  hostedAuthFlow.verdict === VERDICT.SAFE &&
    !hostedAuthFlow.reasons.some((r) => r.id === "offsite_credential_harvest"),
  `scored ${hostedAuthFlow.score}, fired: ${hostedAuthFlow.reasons.map((r) => r.id).join(", ") || "none"}`
);

// False-positive guard #2: this is the exact failure mode the 2026-08-05
// entry in docs/PROGRESS.md describes for credential_request — a real login
// page landing in the same band as phishing. A single-field sign-in form
// with an ordinary amount of real content, posting off-site to a vendor
// nobody's heard of, is what a small bank's own third-party auth backend
// looks like. Off-site-to-an-unrecognized-domain alone must not be enough.
const smallBankOwnAuthVendor = await pageScan(
  "GreenLeaf Community Bank online banking lets members view balances, review transaction history, " +
    "transfer funds between GreenLeaf accounts, and pay bills electronically. Routing number 111000025. " +
    "Branch locations in Millbrook, Denton, and Fairview are open Monday through Friday from 9am to 5pm " +
    "and Saturday from 9am to noon. Reach customer service at 555-0142 during business hours. GreenLeaf " +
    "Community Bank is a member of the FDIC and an Equal Housing Lender. Password.",
  {
    url: "https://greenleafbank.com/login",
    title: "Sign In - GreenLeaf Community Bank",
    credentialFields: ["password"],
    formTargets: ["https://identity.greenleaf-auth.com/submit"],
  }
);
check(
  "a substantial single-field login page posting off-site is not enough on its own",
  smallBankOwnAuthVendor.verdict === VERDICT.SAFE &&
    !smallBankOwnAuthVendor.reasons.some((r) => r.id === "offsite_credential_harvest"),
  `scored ${smallBankOwnAuthVendor.score}, fired: ${smallBankOwnAuthVendor.reasons.map((r) => r.id).join(", ") || "none"}`
);

// The whole-page scan exists to be used on sign-in pages, so the genuine ones
// have to come back clean. They did not: "enter your password" read as a
// credential request, and every real login page on the internet says it.
for (const [name, url, title, text] of [
  ["GitHub", "https://github.com/login", "Sign in to GitHub", "Sign in to GitHub. Enter your password."],
  ["Amazon", "https://www.amazon.in/ap/signin", "Amazon Sign-In", "Sign in. Email or mobile phone number. Password. Forgot your password?"],
  ["HDFC OTP", "https://netbanking.hdfcbank.com/otp", "HDFC Bank NetBanking", "Send OTP to your registered mobile. Enter the OTP below."],
  ["hosted auth", "https://mycompany.atlassian.net/login", "Log in - Jira", "Log in to continue to Jira. Enter your password."],
]) {
  const real = await pageScan(text, {
    url,
    title,
    credentialFields: text.includes("OTP") ? ["otp"] : ["password"],
    formTargets: [],
  });
  check(
    `a genuine sign-in page is not flagged (${name})`,
    real.verdict === VERDICT.SAFE,
    `scored ${real.score}, fired: ${real.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

// The direction of the request is the signal, not the verb. A bank's own
// "Send OTP to your registered mobile" button and a thief's "send me your OTP"
// both contain "send".
for (const [name, message] of [
  ["share your OTP", "Dear customer, please share your OTP to verify your account."],
  ["reply with PIN", "Reply with your ATM PIN to reactivate your card."],
  ["send me your password", "IT here - send me your password so I can fix your mailbox."],
  ["whatsapp me the OTP", "Kindly whatsapp me the OTP you just received."],
]) {
  const msg = await analyzeLocal(message);
  check(
    `a message asking you to hand over a secret still fires (${name})`,
    msg.reasons.some((r) => r.id === "credential_request"),
    `scored ${msg.score}, fired: ${msg.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

const entryInMessage = await analyzeLocal(
  "Enter your password at http://secure-verify.tk/login to restore access."
);
check(
  "an entry verb still convicts in a message, where there is no form",
  entryInMessage.reasons.some((r) => r.id === "credential_request"),
  `fired: ${entryInMessage.reasons.map((r) => r.id).join(", ") || "none"}`
);

const claimMismatch = await analyzeLocal(
  "Your Netflix membership is on hold. Your payment could not be verified. Update your details at https://acct-portal-x9.com/verify to avoid interruption."
);
check(
  "a message claiming a brand but linking elsewhere is flagged",
  claimMismatch.reasons.some((r) => r.id === "brand_claim_mismatch"),
  `fired: ${claimMismatch.reasons.map((r) => r.id).join(", ") || "none"}`
);

const legitRedirect = await analyzeLocal(
  "Team, we've moved our documents to Google Drive. You can sign in at https://intranet.example.com/login with your usual work account."
);
check(
  "an ordinary mail naming a brand and linking internally is not flagged",
  legitRedirect.verdict === VERDICT.SAFE &&
    !legitRedirect.reasons.some((r) => r.id === "brand_claim_mismatch"),
  `scored ${legitRedirect.score}, fired: ${legitRedirect.reasons.map((r) => r.id).join(", ") || "none"}`
);

/* ------------------------------- heuristics -------------------------------- */

const homoglyph = analyzeHeuristics("Sh4re your 0TP c0de immediately to verify your acc0unt");
check(
  "sees through leetspeak obfuscation",
  homoglyph.signals.length > 0,
  `fired: ${homoglyph.signals.map((s) => s.id).join(", ") || "none"}`
);

const exonerated = analyzeHeuristics("Thanks for the update, I'll take a look by Friday.");
check("exonerating rules fire on ordinary mail", exonerated.exonerating.length > 0);

const severe = analyzeHeuristics("As discussed, please share your OTP and card number with me now.");
check(
  "exonerating rules suppressed when a severe signal fires",
  severe.exonerating.length === 0,
  "a 'as discussed' preamble must not discount a credential request"
);

/* --------------------------- tactic-specific rules ------------------------- */
// Five tactics the accuracy benchmark showed had no rule at all. Each is
// conjunctive, so each gets its near-miss: the ordinary message that shares
// most of the vocabulary and must stay clean. "Hi mum, this is my new number"
// is a real thing people send.

const TACTICS = [
  {
    rule: "family_emergency",
    caught: [
      "Hi dad, I broke my screen so I'm texting from a friend's phone. Can you transfer money now?",
      "Hi sis, using a temp number. My salary is delayed and rent is due tonight, transfer 8000 please.",
      "Beta, this is uncle. Your cousin met with an accident, we need money for the operation right away.",
    ],
    clean: [
      "Hi mum, this is my new number, save it. Call me when you're free.",
      "Hey bro, can you send me the photos from the wedding?",
      "Dad, I lost my wallet at the station. Cancelling the cards now, will call you tonight.",
    ],
  },
  {
    rule: "delivery_redispatch_fee",
    caught: [
      "Bluedart: delivery attempt failed. Reschedule and pay re-dispatch charges here.",
      "Amazon: Your package cannot be delivered. Reschedule here.",
      "FedEx notice: address verification required for your shipment. Confirm and pay the handling fee.",
    ],
    clean: [
      "Your package has been delivered and left with the security desk.",
      "Your order has shipped. Track your parcel with the courier using this reference.",
      "Delivery scheduled for Tuesday between 9am and 12pm. Reply RESCHEDULE to change it.",
    ],
  },
  {
    rule: "job_advance_fee",
    caught: [
      "You are shortlisted for a data entry job with weekly salary. Deposit a refundable security amount of 1500 to begin.",
      "Work from home packing job, materials shipped to your address after a small courier deposit.",
      "Earn from YouTube likes! Get paid per video. Join by paying a one time membership of 2500.",
    ],
    clean: [
      "We'd like to invite you to a second interview for the data entry role on Tuesday. No preparation needed.",
      "Your salary for March has been credited to your account.",
      "Thanks for applying. We're moving forward with other candidates for this part-time role.",
    ],
  },
  {
    rule: "refund_callback",
    caught: [
      "Norton antivirus: your subscription auto-renewed for $349. To cancel and refund, call our helpline immediately.",
      "Your order of 42,000 was charged today. If this transaction was not authorized, dial our toll-free number.",
    ],
    clean: [
      "Your subscription renews on 12 March. Manage it any time in your account settings.",
      "Here is your invoice for last month. Reply to this email if anything looks wrong.",
    ],
  },
  {
    rule: "windfall_solicitation",
    caught: [
      "I am an army officer deployed abroad and need a trusted partner to receive 10 million dollars.",
      "I am a widow with terminal illness wishing to donate my late husband's fortune to you.",
    ],
    clean: [
      "The fund returned 8% last year. Your statement is attached.",
      "Our late founder's estate has funded three scholarships; applications open in June.",
    ],
  },
];

for (const { rule, caught, clean } of TACTICS) {
  for (const message of caught) {
    const result = analyzeHeuristics(message);
    check(
      `${rule} fires: ${message.slice(0, 44)}…`,
      result.signals.some((s) => s.id === rule),
      `fired: ${result.signals.map((s) => s.id).join(", ") || "nothing"}`
    );
  }
  for (const message of clean) {
    const result = analyzeHeuristics(message);
    check(
      `${rule} stays quiet: ${message.slice(0, 44)}…`,
      !result.signals.some((s) => s.id === rule),
      `fired: ${result.signals.map((s) => s.id).join(", ") || "nothing"}`
    );
  }
}

// The rules exist to move a verdict, not just to match. These are the messages
// that scored 10-33 before they existed.
for (const message of [
  "Hi dad, I broke my screen so I'm texting from a friend's phone. Can you transfer money now?",
  "Bluedart: delivery attempt failed. Reschedule and pay re-dispatch charges here.",
  "You are shortlisted for a data entry job with weekly salary. Deposit a refundable security amount of 1500.",
]) {
  const result = await analyzeLocal(message);
  check(
    `now flagged end to end: ${message.slice(0, 40)}…`,
    result.verdict !== VERDICT.SAFE,
    `scored ${result.score}`
  );
}

// Four regex gaps found while chasing the accuracy benchmark's curated misses
// down to the exact row responsible (2026-08-16/17's technique): each rule
// looked like it covered a case and silently didn't, on a Devanagari
// loanword or a substring collision rather than a missing whole feature.
for (const [name, message, rule] of [
  [
    "ट्रांसफर (transfer) as a Devanagari send-verb",
    "भाई यह मेरा टेम्परेरी नंबर है, पुराना फोन खराब हो गया। अभी 4000 रुपये ट्रांसफर कर दो, कल वापस कर दूंगा।",
    "family_emergency",
  ],
  [
    "टेम्परेरी (temporary) recognised as an unreachable-number claim",
    "मम्मी यह टेम्परेरी नंबर है मेरा, फोन टूट गया। 5000 रुपये अभी ट्रांसफर करो, वीकेंड तक वापस कर दूंगा।",
    "family_emergency",
  ],
  [
    "नेटबैंकिंग (net banking) suspended, not just 'account' suspended",
    "आपका HDFC नेटबैंकिंग सस्पेंड कर दिया गया है, लिंक पर क्लिक करके डिटेल्स वेरिफाई करें वरना एक्सेस बंद रहेगा।",
    "account_suspension",
  ],
  [
    "net banking suspended (English noun the rule previously only had as 'account')",
    "Aapka SBI net banking suspend ho gaya. Link par click karke details verify kijiye.",
    "account_suspension",
  ],
]) {
  const result = analyzeHeuristics(message);
  check(
    `${rule} fires: ${name}`,
    result.signals.some((s) => s.id === rule),
    `fired: ${result.signals.map((s) => s.id).join(", ") || "nothing"}`
  );
}

// वारंट (warrant) is a substring of वारंटी (warranty) — a bare substring
// match flagged every routine "your warranty registration is complete"
// message, the same class of bug as कस्टम(?!र) vs कस्टमर above.
const warrantyNotice = analyzeHeuristics(
  "आपकी वारंटी रजिस्ट्रेशन सफलतापूर्वक पूरी हो गई है, डिटेल्स आपके ईमेल पर भेज दी गई हैं।"
);
check(
  "वारंटी (warranty) does not trip the वारंट (warrant) police/authority pattern",
  !warrantyNotice.signals.some((s) => s.id === "threat_of_consequence" || s.id === "impersonated_authority"),
  `fired: ${warrantyNotice.signals.map((s) => s.id).join(", ") || "none"}`
);

/* --------------------------- hinglish and devanagari ----------------------- */
// The tactics these rules encode are largely Indian, but every pattern matched
// English wording only, so the same scam in Hinglish tripped nothing at all.
// Measured before: 64% of Hinglish scams missed and 100% of Devanagari ones,
// against 3.6% for English.

for (const [name, message] of [
  ["OTP request", "Sir aapka bank account block ho gaya hai, turant OTP bhejiye verification ke liye."],
  ["UPI collect", "Maine aapko paise bheje hain. Request accept karke apna UPI PIN daaliye."],
  ["digital arrest", "Ye Mumbai cyber cell se hai. Aapke naam par parcel mila hai. Turant call kijiye."],
  ["KYC expiry", "Aapka KYC expire ho gaya hai. Turant update kijiye warna account band ho jayega."],
  ["family emergency", "Papa main hoon, mera phone kho gaya hai. Is naye number par urgent paise bhej do."],
  ["job advance fee", "Ghar baithe kaam kariye, roz 2000 rupaye kamaiye. Registration ke liye 500 bhejiye."],
  ["devanagari OTP", "आपका खाता ब्लॉक हो गया है। तुरंत ओटीपी भेजिए वरना खाता बंद हो जाएगा।"],
  ["devanagari arrest", "साइबर सेल से बोल रहे हैं। आपके नाम पर वारंट है। अभी पैसे ट्रांसफर कीजिए।"],
  ["devanagari lottery", "बधाई हो! आपने 25 लाख की लॉटरी जीती है। प्रोसेसिंग फीस भेजकर दावा करें।"],
]) {
  const result = await analyzeLocal(message);
  check(
    `hinglish/hindi scam is flagged (${name})`,
    result.verdict !== VERDICT.SAFE,
    `scored ${result.score}, fired: ${result.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

for (const [name, message] of [
  ["meeting", "Kal meeting hai 10 baje office me. Please time par aa jaiye."],
  ["family", "Papa main ghar aa raha hoon, khana ready rakhna. 8 baje tak pahunch jaunga."],
  ["photos", "Bhai wedding ki photos bhej do jo tumne kheenchi thi."],
  ["real bill", "Aapka electricity bill 1240 rupaye ka generate hua hai. Due date 15 tarikh hai."],
  ["devanagari meeting", "कल मीटिंग सुबह दस बजे है। कृपया समय पर पहुँचें।"],
  ["devanagari salary", "वेतन खाते में आ गया है, कृपया जाँच लें।"],
]) {
  const result = await analyzeLocal(message);
  check(
    `ordinary hinglish/hindi stays clean (${name})`,
    result.verdict === VERDICT.SAFE,
    `scored ${result.score}, fired: ${result.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

// An exonerating rule that tests for the *absence* of English verbs fires on
// every message not written in English, handing a discount to exactly the
// scams the rules above exist to catch.
const hindiAction = analyzeHeuristics("आपका खाता ब्लॉक हो गया है। तुरंत ओटीपी भेजिए।");
check(
  "no_action_requested does not exonerate a hindi message that demands action",
  !hindiAction.exonerating.some((s) => s.id === "no_action_requested"),
  `exonerating: ${hindiAction.exonerating.map((s) => s.id).join(", ") || "none"}`
);

// The tokenizer reads Devanagari — its vowel signs are Unicode Marks and used
// to split every word into unusable fragments, fixed 2026-08-06 — and as of
// 2026-08-15 the corpus carries 250+ additional Devanagari rows rather than
// 16, so ordinary scam vocabulary ("खाता", "ब्लॉक", "ओटीपी") now survives
// min_df=3 and the 6,000-feature cap. The model has an opinion here instead
// of abstaining. It is not asserted which way that opinion leans — a single
// short message is not what the accuracy benchmark exists to grade, and the
// rule layer, not the model, is what actually catches this one (KYC/account
// block + urgency + a bare OTP demand). This only checks that abstention no
// longer fires on Hindi vocabulary the corpus has actually taught it.
const hindiModel = await analyzeLocal("आपका खाता ब्लॉक हो गया है। तुरंत ओटीपी भेजिए।");
check(
  "the model votes on devanagari it has vocabulary for, instead of abstaining",
  hindiModel.model.available === true,
  `available=${hindiModel.model.available}, p=${hindiModel.model.probability}`
);

// Abstention itself is still load-bearing — this asserts the mechanism still
// works for a script the corpus genuinely has no vocabulary in, not that
// Hindi still triggers it.
const unknownScriptModel = await analyzeLocal(
  "இது ஒரு சோதனை செய்தி, இதற்கு பயிற்சி தரவு இல்லை."
);
check(
  "the model still abstains on a script it has no vocabulary for",
  unknownScriptModel.model.available === false,
  `available=${unknownScriptModel.model.available}, p=${unknownScriptModel.model.probability}`
);

const englishModel = await analyzeLocal("Please confirm the meeting time for tomorrow afternoon.");
check(
  "the model still votes on ordinary english",
  englishModel.model.available === true,
  `available=${englishModel.model.available}`
);

/* -------------------------------- escalation ------------------------------- */

const obvious = await analyzeLocal(SCAMS[0][1]);
check(
  "does not escalate an obvious scam",
  !shouldEscalate(obvious) || obvious.score <= 80,
  `score ${obvious.score} — clear cases should not spend API budget`
);

const clean = await analyzeLocal(LEGIT[0][1]);
check("does not escalate obviously clean mail", !shouldEscalate(clean), `score ${clean.score}`);

/* ---------------------------------- edges ---------------------------------- */

const empty = await analyzeLocal("");
check("empty input is safe, not crashing", empty.verdict === VERDICT.SAFE);

const long = await analyzeLocal("word ".repeat(5000));
check("handles very long input", typeof long.score === "number" && !Number.isNaN(long.score));

const unicode = await analyzeLocal("आपका खाता निलंबित कर दिया गया है। तुरंत OTP साझा करें।");
check("handles non-Latin script without crashing", typeof unicode.score === "number");

/* ------------------- a failed cloud call must not claim privacy ------------- */
// The result of a failed second opinion used to inherit tier "on-device" from
// the local verdict, and both the popup and the in-page warning render that
// tier as "nothing left your computer". The text had already gone to
// Anthropic. Of everything this extension says, that sentence is the one that
// must never be false, so the tier is asserted here rather than trusted.

// Something uncertain enough that the cloud tier is actually consulted — the
// local layers have to land in the escalation band or `analyze()` never calls
// out at all and these cases would pass without testing anything.
const UNCERTAIN = "We could not process your last payment. Update your card to avoid interruption.";

const escalates = await analyzeLocal(UNCERTAIN);
check("precondition: the fixture reaches the uncertain band", shouldEscalate(escalates),
  `score ${escalates.score}`);

const answered = await analyze(UNCERTAIN, {
  cloud: async () => {
    const err = new Error("Rate limited by the Claude API — try again shortly.");
    err.sent = true; // Anthropic replied, so the message certainly left
    throw err;
  },
});
check("a failed cloud call no longer reports the on-device tier",
  answered.tier === "cloud-failed", `tier=${answered.tier}`);
check("a reply from Anthropic is recorded as having been reached",
  answered.cloudReached === true);
check("the error still reaches the user", Boolean(answered.cloudError));
check("the local verdict survives the failure", answered.verdict === escalates.verdict);

const unreachable = await analyze(UNCERTAIN, {
  cloud: async () => {
    throw new Error("Failed to fetch"); // untagged: the request may never have left
  },
});
check("an unreachable API is also not reported as on-device",
  unreachable.tier === "cloud-failed", `tier=${unreachable.tier}`);
check("and it does not claim the message was sent when it cannot know",
  unreachable.cloudReached === false);

const untouched = await analyze(UNCERTAIN, {});
check("with no cloud analyzer the tier stays on-device", untouched.tier === "on-device");
check("and carries no cloud error", untouched.cloudError === undefined);

/* -------------------------- network-consent features ------------------------ */

const { URL_SHORTENERS } = await import(join(ext, "engine", "urls.js"));
const { SHORTENER_ORIGINS, isShortenerUrl } = await import(join(ext, "engine", "shortener.js"));
const { parseFeed, matchUrlhaus } = await import(join(ext, "engine", "urlhaus.js"));

// manifest.json's optional_host_permissions has to be kept in sync by hand
// (Chrome requires origins statically declared; there's no build step to
// generate it from URL_SHORTENERS) — this is the drift check the comments in
// urls.js and shortener.js promise.
const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf-8"));
const manifestShortenerOrigins = manifest.optional_host_permissions.filter((o) =>
  [...URL_SHORTENERS].some((d) => o === `https://${d}/*`)
);
check(
  "manifest.json declares exactly the shortener origins URL_SHORTENERS recognizes",
  manifestShortenerOrigins.length === URL_SHORTENERS.size &&
    SHORTENER_ORIGINS.every((o) => manifestShortenerOrigins.includes(o)),
  `manifest has ${manifestShortenerOrigins.length}, URL_SHORTENERS has ${URL_SHORTENERS.size}`
);
check(
  "manifest.json declares the urlhaus origin",
  manifest.optional_host_permissions.includes("https://urlhaus.abuse.ch/*")
);

check("isShortenerUrl recognizes a known shortener", isShortenerUrl("https://bit.ly/abc123"));
check("isShortenerUrl rejects an ordinary domain", !isShortenerUrl("https://example.com/abc123"));

/* -- shortener resolution feeds the resolved destination into URL scoring -- */

const resolved = await analyze("Your PayPal account has been limited. Restore access here: https://bit.ly/xyz", {
  resolveShortener: async () => ({
    resolved: true,
    destinations: new Map([["https://bit.ly/xyz", "https://paypa1-secure.com/login"]]),
  }),
});
check("shortenerResolved is set once a destination is found", resolved.shortenerResolved === true);
check(
  "the resolved destination is scored, not just the shortener link",
  resolved.reasons.some((r) => r.id === "lookalike_domain"),
  resolved.reasons.map((r) => r.id).join(",")
);

const notShortened = await analyze("Ordinary text with no links.", {
  resolveShortener: async () => ({ resolved: false, destinations: new Map() }),
});
check("shortenerResolved stays false when nothing was resolved", notShortened.shortenerResolved === false);

const shortenerFailed = await analyze("Check this out: https://bit.ly/xyz", {
  resolveShortener: async () => {
    throw new Error("network unreachable");
  },
});
check(
  "a failed shortener resolution degrades gracefully, not a crash",
  shortenerFailed.shortenerResolved === false && typeof shortenerFailed.score === "number"
);

const noResolver = await analyze("Check this out: https://bit.ly/xyz", {});
check("with no resolver configured, shortenerResolved is false", noResolver.shortenerResolved === false);

/* --------------------------------- urlhaus ---------------------------------- */

check(
  "parseFeed reads one URL per plain-text line and skips comments",
  (() => {
    const urls = parseFeed("# comment\nhttps://evil.example/payload\n\nhttps://also-evil.example/x\n");
    return urls.length === 2 && urls.includes("https://evil.example/payload");
  })()
);

check(
  "parseFeed also reads the URL out of a CSV row, format unknown in advance",
  (() => {
    const urls = parseFeed('"1","2026-01-01","https://evil.example/payload","online","","malware_download"');
    return urls.length === 1 && urls[0] === "https://evil.example/payload";
  })()
);

check(
  "matchUrlhaus finds an exact hit, ignoring a trailing slash",
  matchUrlhaus(["https://evil.example/payload/"], { entries: ["https://evil.example/payload"] }) ===
    "https://evil.example/payload"
);
check("matchUrlhaus returns null with no feed", matchUrlhaus(["https://evil.example/payload"], null) === null);
check(
  "matchUrlhaus returns null when nothing matches",
  matchUrlhaus(["https://safe.example/"], { entries: ["https://evil.example/payload"] }) === null
);

const urlhausHit = await analyzeLocal("Download your invoice: https://evil.example/payload", {
  urlhausFeed: { entries: ["https://evil.example/payload"] },
});
check(
  "a URLhaus feed match convicts on its own",
  urlhausHit.verdict === VERDICT.DANGEROUS,
  `score ${urlhausHit.score}`
);
check(
  "the urlhaus_match signal is reported",
  urlhausHit.reasons.some((r) => r.id === "urlhaus_match")
);

const urlhausNoFeed = await analyzeLocal("Download your invoice: https://evil.example/payload");
check(
  "with no feed loaded, the same link is not flagged as a urlhaus match",
  !urlhausNoFeed.reasons.some((r) => r.id === "urlhaus_match")
);

/* ------------- legitimate mail and real sites must stay unflagged ----------- */
// Each of these was a measured false positive on held-out data — see
// tests/test_holdout.mjs, which grades the whole genre. These pin the specific
// rule that was wrong, so a regression names itself instead of moving a rate.

// A bank's own OTP message ends with the warning *not* to share the code, which
// put a transmission verb next to a credential noun and read as the theft it
// warns against. All five held-out bank OTP messages were flagged this way,
// three of them "dangerous".
for (const [name, message] of [
  ["English", "558104 is your one time password to login to your ICICI Bank account. This OTP is valid for 5 minutes. Never share your OTP with anyone."],
  ["with the do-not-share footer", "Your OTP for the transaction of Rs 2,450.00 at BIGBAZAAR is 774512. Do not share this OTP with anyone including bank staff."],
  ["Hinglish", "Aapke HDFC account ke liye OTP 210945 hai. Kisi ko na bataye, bank kabhi OTP nahi maangta."],
  ["Devanagari", "ग्रोसरी स्टोर पर कार्ड ट्रांजैक्शन के लिए OTP 55219 है, बैंक स्टाफ सहित किसी को न बताएं।"],
]) {
  const otp = await analyzeLocal(message);
  check(
    `a bank delivering an OTP is not flagged (${name})`,
    otp.verdict === VERDICT.SAFE,
    `scored ${otp.score}, fired: ${otp.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

// The other direction of the same rule: stripping the advice clause must not
// strip the ask that follows it.
const bankFooterOverAsk = await analyzeLocal(
  "Never share your OTP with anyone. Now please send me the OTP you just received so I can verify your account."
);
check(
  "a real bank footer pasted above an actual ask does not launder the ask",
  bankFooterOverAsk.reasons.some((r) => r.id === "credential_request"),
  `fired: ${bankFooterOverAsk.reasons.map((r) => r.id).join(", ") || "none"}`
);

// A prize is not a payment method. gift_card_payment carries the heaviest
// weight any rule has, and it fired on the noun alone.
const giftCardPrize = await analyzeLocal(
  "This Week's Movie Trivia Question from All Things New England. Hello Friends! Answer correctly for a chance to win a gift card."
);
check(
  "a newsletter offering a gift card as a prize is not a gift-card payment demand",
  !giftCardPrize.reasons.some((r) => r.id === "gift_card_payment"),
  `scored ${giftCardPrize.score}, fired: ${giftCardPrize.reasons.map((r) => r.id).join(", ") || "none"}`
);

// A short-lived link is a security control, not a countdown.
const verificationLink = await analyzeLocal(
  "Verify your email address. Please confirm this email address to finish setting up your Bitwarden account. This link expires in 24 hours."
);
check(
  "a verification email whose link expires is not flagged for urgency",
  verificationLink.verdict === VERDICT.SAFE &&
    !verificationLink.reasons.some((r) => r.id === "artificial_urgency"),
  `scored ${verificationLink.score}, fired: ${verificationLink.reasons.map((r) => r.id).join(", ") || "none"}`
);
const accountExpiry = await analyzeLocal(
  "Your account expires in 24 hours unless you confirm your details now."
);
check(
  "an *account* expiring still counts as manufactured urgency",
  accountExpiry.reasons.some((r) => r.id === "artificial_urgency"),
  `fired: ${accountExpiry.reasons.map((r) => r.id).join(", ") || "none"}`
);

// "urgently" modifying "needed" is a reporter's judgment about a shortage,
// not a countdown aimed at the reader — ambient false positive from a 2002
// news-aggregator mailing list ("larger studies are urgently needed").
const urgentlyNeeded = await analyzeLocal(
  "Researchers say fresh clinical trial data is urgently needed before regulators can approve a wider rollout of the vaccine."
);
check(
  "news calling for data that is urgently needed is not manufactured urgency",
  urgentlyNeeded.verdict === VERDICT.SAFE &&
    !urgentlyNeeded.reasons.some((r) => r.id === "artificial_urgency"),
  `scored ${urgentlyNeeded.score}, fired: ${urgentlyNeeded.reasons.map((r) => r.id).join(", ") || "none"}`
);

// "X should immediately Y" is a recommendation about a third party's future
// action, not a directive at the reader — ambient false positive from a BBC
// click-through ("the government should immediately announce...").
const shouldImmediately = await analyzeLocal(
  "Op-ed: the city council should immediately expand recycling collection to every neighborhood, community groups argue."
);
check(
  "a third party being told what it should immediately do is not manufactured urgency",
  shouldImmediately.verdict === VERDICT.SAFE &&
    !shouldImmediately.reasons.some((r) => r.id === "artificial_urgency"),
  `scored ${shouldImmediately.score}, fired: ${shouldImmediately.reasons.map((r) => r.id).join(", ") || "none"}`
);

// A URL is an address, not prose — "urgent" inside a link's hostname is not
// the reader being rushed. Ambient false positive from a mailing-list
// signature linking a Belgian radio station, http://urgent.rug.ac.be/.
const urgentInUrl = await analyzeLocal(
  "This week's newsletter archive is up: http://urgent-updates.example.com/archive/12 has the full roundup."
);
check(
  "the word urgent appearing only inside a URL is not manufactured urgency",
  urgentInUrl.verdict === VERDICT.SAFE &&
    !urgentInUrl.reasons.some((r) => r.id === "artificial_urgency"),
  `scored ${urgentInUrl.score}, fired: ${urgentInUrl.reasons.map((r) => r.id).join(", ") || "none"}`
);

// Police verification is a step in getting a passport, not a threat.
const passport = await analyzeLocal("आपका पासपोर्ट आवेदन स्वीकृत हो गया है। पुलिस सत्यापन के बाद पासपोर्ट भेजा जाएगा।");
check(
  "a passport approval mentioning police verification is not a threat",
  passport.verdict === VERDICT.SAFE &&
    !passport.reasons.some((r) => r.id === "threat_of_consequence"),
  `scored ${passport.score}, fired: ${passport.reasons.map((r) => r.id).join(", ") || "none"}`
);

// "Delivery fee" is a line item on every checkout page in existence; it used to
// convict at weight 2.0 on its own.
const checkout = await analyzeLocal(
  "Your cart. Item total Rs 320. Delivery fee Rs 30. GST and charges Rs 42. To pay Rs 392. Proceed to pay."
);
check(
  "a checkout page listing a delivery fee is not an advance-fee scam",
  !checkout.reasons.some((r) => r.id === "advance_fee"),
  `scored ${checkout.score}, fired: ${checkout.reasons.map((r) => r.id).join(", ") || "none"}`
);
const loanFee = await analyzeLocal(
  "Your loan of 2 lakh is pre-approved with zero paperwork. Pay the file processing charge to get disbursal in 30 minutes."
);
check(
  "a loan asking for a processing charge up front still fires advance_fee",
  loanFee.reasons.some((r) => r.id === "advance_fee"),
  `fired: ${loanFee.reasons.map((r) => r.id).join(", ") || "none"}`
);

// login.microsoftonline.com is where every Microsoft 365 sign-in lands. It was
// missing from the brand's domain list, so the real page read as a harvest.
const microsoftReal = await pageScan(
  "Sign in to continue to Outlook. Email, phone, or Skype. No account? Create one! Can't access your account?",
  {
    url: "https://login.microsoftonline.com/",
    title: "Sign in to your account",
    credentialFields: ["password"],
    formTargets: ["https://login.microsoftonline.com/common/login"],
  }
);
check(
  "Microsoft's real sign-in domain is not treated as impersonation",
  microsoftReal.verdict === VERDICT.SAFE &&
    !microsoftReal.reasons.some((r) => r.id === "brand_impersonation"),
  `scored ${microsoftReal.score}, fired: ${microsoftReal.reasons.map((r) => r.id).join(", ") || "none"}`
);

// On the authority's own domain the claim is true.
const taxPortal = await pageScan(
  "e-Filing Home Page, Income Tax Department, Government of India. Login. Enter your User ID (PAN). File your Income Tax Return.",
  {
    url: "https://www.incometax.gov.in/iec/foportal/",
    title: "Income Tax Department - e-Filing",
    credentialFields: ["password"],
    formTargets: ["https://www.incometax.gov.in/iec/foportal/login"],
  }
);
check(
  "the Income Tax department's own portal is not impersonating the Income Tax department",
  taxPortal.verdict === VERDICT.SAFE &&
    !taxPortal.reasons.some((r) => r.id === "impersonated_authority"),
  `scored ${taxPortal.score}, fired: ${taxPortal.reasons.map((r) => r.id).join(", ") || "none"}`
);
const taxMessage = await analyzeLocal(
  "Income Tax Department notice: you owe unpaid taxes and a warrant has been issued against you."
);
check(
  "the same claim in a message, with no domain vouching for it, still fires",
  taxMessage.reasons.some((r) => r.id === "impersonated_authority"),
  `fired: ${taxMessage.reasons.map((r) => r.id).join(", ") || "none"}`
);

// Every real login page on the internet has /login in its path.
const bankLoginPath = await pageScan(
  "ICICI Bank Internet Banking. User ID. Password. Login. Caution: ICICI Bank never asks for your PIN, OTP, CVV or password. Report suspicious calls immediately.",
  {
    url: "https://infinity.icicibank.com/corp/Login.jsp",
    title: "ICICI Bank Internet Banking",
    credentialFields: ["password"],
    formTargets: ["https://infinity.icicibank.com/corp/Login.jsp"],
  }
);
check(
  "a bank's own login URL does not score for having /login in the path",
  bankLoginPath.verdict === VERDICT.SAFE &&
    !bankLoginPath.reasons.some((r) => r.id === "credential_path"),
  `scored ${bankLoginPath.score}, fired: ${bankLoginPath.reasons.map((r) => r.id).join(", ") || "none"}`
);
const unknownLoginPath = await analyzeLocal("Restore access here: https://secure-verify-9f2.tk/login");
check(
  "an unknown domain with a login path still scores",
  unknownLoginPath.reasons.some((r) => r.id === "credential_path"),
  `fired: ${unknownLoginPath.reasons.map((r) => r.id).join(", ") || "none"}`
);

/* ------------- Devanagari scams the rules used to read as nothing ----------- */
// 14 of 18 remaining Devanagari misses fired no rule at all. Each of these
// pins the specific vocabulary gap that let one through — the recurring shape
// being a Devanagari-spelled loanword the Latin half of the pattern already
// covered ("शेयर करें" for share, "सिक्योरिटी" for a security deposit).

for (const [name, message, rule] of [
  ["OTP शेयर करें", "सर आपका रिफंड बाकी है, हमारे एग्जीक्यूटिव को कॉलबैक करें और OTP शेयर करें।", "credential_request"],
  ["ID कार्ड fee, mixed script", "नमस्ते, HR टीम से बोल रही हूं, आपका इंटरव्यू सिलेक्ट हो गया है ऑनलाइन सर्वे जॉब के लिए। ID कार्ड बनवाने के लिए 599 रुपये भेजिए।", "job_advance_fee"],
  ["security deposit as सिक्योरिटी", "घर बैठे प्रोडक्ट लिस्टिंग का काम करें, 25000 प्रति माह। अकाउंट एक्टिवेशन के लिए 1100 रुपये सिक्योरिटी जमा करें।", "job_advance_fee"],
  ["refund callback", "आपके सब्सक्रिप्शन का 2199 रुपये कटा है, कैंसिल कराने के लिए कस्टमर केयर को कॉल करें।", "refund_callback"],
  ["payroll redirect", "टीम, हमारा पेरोल पोर्टल बदल गया है, कृपया इस नए लिंक पर अपना सैलरी अकाउंट दोबारा रजिस्टर करें।", "payment_detail_change"],
  ["APK को डाउनलोड करके", "आयुष्मान भारत कार्ड फ्री बनवाएं, 5 लाख तक का इलाज मुफ्त। रजिस्ट्रेशन के लिए इस APK को डाउनलोड करके अपनी डिटेल भरें।", "unexpected_attachment_or_install"],
  ["घर वालों को मत बताना", "चाचा जी, मैं रोहन बोल रहा हूं, नया सिम लिया है। घर वालों को मत बताना, 25000 रुपये भेज दो।", "secrecy_request"],
]) {
  const scam = await analyzeLocal(message);
  check(
    `a Devanagari scam fires ${rule} (${name})`,
    scam.reasons.some((r) => r.id === rule),
    `scored ${scam.score}, fired: ${scam.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

// The English fix for "this link expires in 24 hours" had no Devanagari half,
// so a food-delivery app's own verification code was flagged for urgency.
const devaCodeExpiry = await analyzeLocal("फूड डिलीवरी ऐप के लिए वेरिफिकेशन कोड 3391 है, जल्दी एक्सपायर हो जाएगा।");
check(
  "a Devanagari verification code that expires is not manufactured urgency",
  devaCodeExpiry.verdict === VERDICT.SAFE &&
    !devaCodeExpiry.reasons.some((r) => r.id === "artificial_urgency"),
  `scored ${devaCodeExpiry.score}, fired: ${devaCodeExpiry.reasons.map((r) => r.id).join(", ") || "none"}`
);
const devaAccountExpiry = await analyzeLocal("आपका अकाउंट जल्दी एक्सपायर हो जाएगा, तुरंत KYC अपडेट करें।");
check(
  "a Devanagari *account* expiring still counts as urgency",
  devaAccountExpiry.reasons.some((r) => r.id === "artificial_urgency"),
  `fired: ${devaAccountExpiry.reasons.map((r) => r.id).join(", ") || "none"}`
);

// no_action_requested is absence-based, so its verb list has to keep up with
// the presence-based rules or it quietly discounts the scams they catch.
for (const [name, message] of [
  ["फॉर्म भरें", "बैंक ऑफ बड़ौदा से: आपके खाते में KYC मिसमैच है, निवेश फ्रीज होने से बचने के लिए फॉर्म तुरंत भरें।"],
  ["लॉगिन करें", "आपके ऑर्डर की पेमेंट डबल कट गई, 899 रुपये वापस पाने के लिए यहां क्लिक करके नेट बैंकिंग लॉगिन करें।"],
  ["सत्यापित करना है", "यह डायरेक्टर ऑफिस से है, हर कर्मचारी को अपना IFSC कोड और खाता नंबर इस फॉर्म में सत्यापित करना है।"],
]) {
  const asked = await analyzeLocal(message);
  check(
    `a Devanagari message that asks for something is not exonerated (${name})`,
    !asked.exonerating.some((r) => r.id === "no_action_requested"),
    `exonerating: ${asked.exonerating.map((r) => r.id).join(", ") || "none"}`
  );
}

/* ------------- the last six Devanagari misses, and their opposites ---------- */

// normalize() folds digits onto letters but leaves their punctuation, so the
// decimal point in an amount used to split a sentence in half and put the two
// halves of a proximity-gated rule out of reach of each other.
const decimalAmount = await analyzeLocal(
  "किसान क्रेडिट लोन स्कीम में आपका 1.5 लाख अप्रूव हुआ है, GST क्लियरेंस के लिए 750 रुपये सरकारी खाते में भेजें।"
);
check(
  "a decimal in the amount no longer breaks the same-sentence gate",
  decimalAmount.reasons.some((r) => r.id === "advance_fee"),
  `scored ${decimalAmount.score}, fired: ${decimalAmount.reasons.map((r) => r.id).join(", ") || "none"}`
);

for (const [name, message, rule] of [
  ["OLX collect request", "मैडम आपका सामान बेच दिया OLX पर, पेमेंट भेज रहा हूं आपको, बस स्क्रीन पर आया रिक्वेस्ट एक्सेप्ट कर दीजिए, 6000 रुपये है।", "upi_collect_request"],
  ["refund lure without the word refund", "आपके ऑर्डर की पेमेंट डबल कट गई, 899 रुपये एक्स्ट्रा वापस पाने के लिए यहां क्लिक करके नेट बैंकिंग लॉगिन करें।", "prize_or_windfall"],
  ["passbook upload", "स्वनिधि योजना के तहत 10000 रुपये का बिना ब्याज लोन मिल रहा है, आवेदन के लिए इस लिंक पर बैंक पासबुक फोटो अपलोड करें।", "payment_detail_change"],
  ["IFSC harvest", "यह डायरेक्टर ऑफिस से है, बोनस के लिए हर कर्मचारी को अपना IFSC कोड और खाता नंबर इस फॉर्म में सत्यापित करना है।", "payment_detail_change"],
  ["telecom cut-off", "Vi नेटवर्क अलर्ट: आपका सिम कार्ड री-वेरिफिकेशन के लिए फ्लैग हुआ है, कल शाम तक प्रोसेस पूरी न होने पर सेवाएं बंद होंगी।", "account_suspension"],
]) {
  const scam = await analyzeLocal(message);
  check(
    `a Devanagari scam fires ${rule} (${name})`,
    scam.reasons.some((r) => r.id === rule),
    `scored ${scam.score}, fired: ${scam.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

// Both of these fired on the first version of the two branches above, and are
// the reason each carries an extra condition. A meeting invite uses the exact
// same imperative as the collect-request scam; a maintenance window states the
// same outcome as the telecom threat. Money, and conditionality on the reader's
// inaction, are what separate them.
const meetingInvite = await analyzeLocal("कृपया कैलेंडर पर भेजी गई मीटिंग रिक्वेस्ट एक्सेप्ट कर दीजिए, कल दोपहर 3 बजे की है।");
check(
  "a meeting invite is not a UPI collect request",
  meetingInvite.verdict === VERDICT.SAFE && !meetingInvite.reasons.some((r) => r.id === "upi_collect_request"),
  `scored ${meetingInvite.score}, fired: ${meetingInvite.reasons.map((r) => r.id).join(", ") || "none"}`
);
const maintenance = await analyzeLocal("रखरखाव कार्य के कारण कल रात 2 से 4 बजे तक ऑनलाइन सेवाएं बंद रहेंगी। असुविधा के लिए खेद है।");
check(
  "a scheduled maintenance window is not account suspension",
  maintenance.verdict === VERDICT.SAFE && !maintenance.reasons.some((r) => r.id === "account_suspension"),
  `scored ${maintenance.score}, fired: ${maintenance.reasons.map((r) => r.id).join(", ") || "none"}`
);

/* --------------- the last English misses, and two general bugs ------------- */

// Gmail, Word and iOS all autocorrect ' to U+2019, so real mail overwhelmingly
// carries the curly form — and every pattern written with an ASCII apostrophe
// silently stopped matching the text it was written for.
const curlyApostrophe = await analyzeLocal("You’ve won a free iPhone! Click the link to claim now.");
check(
  "a curly apostrophe still matches the patterns written with a straight one",
  curlyApostrophe.reasons.some((r) => r.id === "prize_or_windfall"),
  `scored ${curlyApostrophe.score}, fired: ${curlyApostrophe.reasons.map((r) => r.id).join(", ") || "none"}`
);

for (const [name, message, rule] of [
  ["unusual activity pretext", "We detected unusual activity in your bank account. Login to confirm.", "account_suspension"],
  ["SIM deactivation", "Your SIM will be deactivated in 24 hours due to pending verification. Call this number and complete e-KYC to keep your number.", "account_suspension"],
  ["billing info update", "Update your billing info to avoid service interruption.", "payment_detail_change"],
  ["English payroll redirect", "Team, our payroll portal changed. Re-register your salary account on the new site to receive this month's credit.", "payment_detail_change"],
  ["bank details, no adjective", "Aapka mobile number lucky draw me select hua hai. Bank details bhejiye prize ke liye.", "payment_detail_change"],
  ["lucky draw", "Aapka mobile number lucky draw me select hua hai. Bank details bhejiye prize ke liye.", "prize_or_windfall"],
  ["traffic challan waiver", "Get your traffic challan waived off. Official settlement portal, pay half the amount here today only.", "threat_of_consequence"],
  ["password expiry pretext", "Your iCloud password will expire today. Reset it now: track-package.info", "artificial_urgency"],
]) {
  const scam = await analyzeLocal(message);
  check(
    `an English/Hinglish scam fires ${rule} (${name})`,
    scam.reasons.some((r) => r.id === rule),
    `scored ${scam.score}, fired: ${scam.reasons.map((r) => r.id).join(", ") || "none"}`
  );
}

// A *password* expiring is a phishing pretext; a *link* expiring is a security
// control the sender built. Only the second is stripped.
const resetLinkExpiry = await analyzeLocal(
  "We received a request to reset your password. This link expires in 60 minutes. If you did not request it, ignore this email."
);
check(
  "a reset link expiring is still not urgency, even though the mail says password",
  resetLinkExpiry.verdict === VERDICT.SAFE,
  `scored ${resetLinkExpiry.score}, fired: ${resetLinkExpiry.reasons.map((r) => r.id).join(", ") || "none"}`
);

// "to avoid interruption" is what a real dunning email says when a card
// expires, and what the Netflix-lookalike phish says. The text does not
// separate them; the URL does.
const realDunning = await analyzeLocal(
  "Your Adobe Creative Cloud payment could not be processed. Please update your payment method in your account to avoid interruption."
);
check(
  "a real dunning email is not account suspension",
  realDunning.verdict === VERDICT.SAFE && !realDunning.reasons.some((r) => r.id === "account_suspension"),
  `scored ${realDunning.score}, fired: ${realDunning.reasons.map((r) => r.id).join(", ") || "none"}`
);

// The unusual-activity branch needs the action half, or every real bank's own
// security alert fires on it.
const realSecurityAlert = await analyzeLocal(
  "We noticed unusual activity on your account and have already blocked the attempt. No action is required from you."
);
check(
  "a bank's own unusual-activity alert with nothing to do is not flagged",
  realSecurityAlert.verdict === VERDICT.SAFE &&
    !realSecurityAlert.reasons.some((r) => r.id === "account_suspension"),
  `scored ${realSecurityAlert.score}, fired: ${realSecurityAlert.reasons.map((r) => r.id).join(", ") || "none"}`
);

/* ---------------------------------- report --------------------------------- */

const total = passed + failures.length;
console.log(`\n${passed}/${total} checks passed`);

if (failures.length) {
  console.log("\nFailures:");
  failures.forEach((f) => console.log(`  ✗ ${f}`));
  process.exit(1);
}
console.log("All engine checks passed.");
