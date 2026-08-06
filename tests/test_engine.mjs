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

const { analyze, analyzeLocal, shouldEscalate, VERDICT } = await import(join(ext, "engine", "engine.js"));
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

// The tokenizer now reads Devanagari — its vowel signs are Unicode Marks and
// used to split every word into unusable fragments — but the vocabulary still
// has no Hindi in it, because 16 Devanagari rows in a 3,248-row corpus do not
// survive min_df=3 and a 6,000-feature cap. So the terms are correct and the
// model has no weight for any of them: it still yields almost no known terms
// and a probability just under 0.5, which would *subtract* points from a
// message it has no opinion about. The abstention is what keeps that from
// happening, and it is load-bearing until the corpus carries enough Hindi to
// learn from. Fixing the tokenizer was necessary for that and not sufficient.
const hindiModel = await analyzeLocal("आपका खाता ब्लॉक हो गया है। तुरंत ओटीपी भेजिए।");
check(
  "the model abstains on text it has no vocabulary for",
  hindiModel.model.available === false,
  `available=${hindiModel.model.available}, p=${hindiModel.model.probability}`
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

/* ---------------------------------- report --------------------------------- */

const total = passed + failures.length;
console.log(`\n${passed}/${total} checks passed`);

if (failures.length) {
  console.log("\nFailures:");
  failures.forEach((f) => console.log(`  ✗ ${f}`));
  process.exit(1);
}
console.log("All engine checks passed.");
