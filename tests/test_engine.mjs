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

const { analyzeLocal, shouldEscalate, VERDICT } = await import(join(ext, "engine", "engine.js"));
const { analyzeUrls, editDistance, registrableDomain } = await import(join(ext, "engine", "urls.js"));
const { analyzeHeuristics } = await import(join(ext, "engine", "heuristics.js"));

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

/* ------------------------------ URL analysis ------------------------------- */

check("editDistance basic", editDistance("paypal", "paypa1") === 1);
check("editDistance early bail", editDistance("a", "abcdefghij", 2) > 2);
check("registrableDomain simple", registrableDomain("mail.google.com") === "google.com");
check("registrableDomain co.uk", registrableDomain("shop.example.co.uk") === "example.co.uk");
check("registrableDomain bare", registrableDomain("example.com") === "example.com");

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

const punycode = analyzeUrls("visit https://xn--pypal-4ve.com/login");
check("detects punycode", punycode.signals.some((s) => s.id === "punycode_host"));

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

const dedup = analyzeUrls("see http://bit.ly/a", ["http://bit.ly/a", "http://bit.ly/b"]);
check(
  "shortener signal is not multiplied by repeated links",
  dedup.signals.filter((s) => s.id === "url_shortener").length === 1,
  `${dedup.signals.filter((s) => s.id === "url_shortener").length} shortener signals`
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

/* ---------------------------------- report --------------------------------- */

const total = passed + failures.length;
console.log(`\n${passed}/${total} checks passed`);

if (failures.length) {
  console.log("\nFailures:");
  failures.forEach((f) => console.log(`  ✗ ${f}`));
  process.exit(1);
}
console.log("All engine checks passed.");
