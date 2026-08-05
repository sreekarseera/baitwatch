// Verdict engine — fuses the three detection layers into one decision.
//
// Design note: the layers are deliberately not averaged. Heuristics and URL
// signals are *evidence of a specific tactic* and are allowed to convict on
// their own (a gift-card request is a scam regardless of what a bag-of-words
// model thinks). The statistical model is a prior that nudges borderline
// cases. Fusing them any other way lets a confident-but-wrong model bury a
// signal the user needed to see.

import { analyzeHeuristics } from "./heuristics.js";
import { analyzeUrls } from "./urls.js";
import { analyzeImpersonation } from "./impersonation.js";
import { classify } from "./model.js";

export const VERDICT = {
  DANGEROUS: "dangerous",
  SUSPICIOUS: "suspicious",
  SAFE: "safe",
};

// Risk thresholds on the fused 0–100 scale.
const DANGEROUS_AT = 65;
const SUSPICIOUS_AT = 35;

// Below this the local layers are confident enough that escalating to the
// cloud tier would just spend the user's API budget re-confirming.
const ESCALATE_LOW = 25;
const ESCALATE_HIGH = 80;

// Most the statistical layer can move a verdict. Deliberately below
// DANGEROUS_AT: the model can raise a flag alone, never a red card alone.
const MODEL_MAX_PULL = 50;

// On a whole-page scan the model gets far less authority, because it is being
// asked about text unlike anything it was trained on. It learned from email;
// a sign-in page is nav chrome, form labels and legal boilerplate. Raising the
// message-side pull to 50 pushed real Amazon and HDFC login pages to 41 and 43
// — the model reading "password... verify... account" on a page where those
// words are simply the furniture. The rule layers already read page structure
// properly and are what should decide there.
const MODEL_MAX_PULL_PAGE = 22;

// Vocabulary terms a message must hit before the model's opinion counts at all.
// Three is low on purpose: it is meant to catch text the model genuinely cannot
// read — Hindi script, mostly — not to second-guess short messages.
const MIN_KNOWN_TERMS = 3;

function squash(rawScore) {
  // Map an unbounded positive weight sum onto 0–100 with diminishing returns,
  // so a message with eight weak signals can't outrank one with a single
  // decisive one.
  return 100 * (1 - Math.exp(-rawScore / 2.6));
}

/**
 * Run the local (free, offline, private) layers.
 * @param {string} text
 * @param {{extraUrls?: string[], page?: object}} [opts] `extraUrls` carries link
 *   targets and the page address during a whole-page scan — see analyzeUrls.
 *   `page` carries the page's own address, title, form targets, and which kinds
 *   of credential field it contains — see analyzeImpersonation.
 * @returns {Promise<object>} verdict object
 */
export async function analyzeLocal(text, opts = {}) {
  const heuristics = analyzeHeuristics(text, {
    hasCredentialForm: (opts.page?.credentialFields || []).length > 0,
  });
  const urls = analyzeUrls(text, opts.extraUrls || []);

  // Runs after the URL layer so it can see which brands were already flagged
  // there: a lookalike domain and an impersonated page are one finding.
  const impersonation = analyzeImpersonation(text, {
    page: opts.page,
    urls: urls.urls,
    urlBrands: new Set(urls.signals.map((s) => s.brand).filter(Boolean)),
  });

  // MIN_KNOWN_TERMS: below this the model has not read enough of the message to
  // have an opinion, and its probability is really just the intercept. Letting
  // it vote anyway is not neutral — the intercept sits slightly below 0.5, so
  // it subtracts points from text it cannot parse.
  let model = { probability: 0.5, matchedTerms: [], knownTerms: 0, available: false };
  try {
    const classified = await classify(text);
    model = { ...classified, available: classified.knownTerms >= MIN_KNOWN_TERMS };
  } catch (err) {
    // A missing/corrupt model artifact must not take the whole extension
    // down — the rule layers are the ones that carry the explanations.
    console.warn("[BaitWatch] on-device model unavailable:", err);
  }

  const ruleScore = squash(heuristics.score + urls.score + impersonation.score);

  // The model contributes at most MODEL_MAX_PULL points, in whichever
  // direction it is confident about.
  //
  // This was 22 while the model was 281 rows scoring 93% +/- 18% — at that
  // variance it had not earned the authority to raise a flag by itself. The
  // consequence was structural, not conservative: 22 is below SUSPICIOUS_AT,
  // so a message that tripped no rule could never be flagged however certain
  // the model was, and short pretext-only phishing ("We detected unusual
  // activity in your bank account. Login to confirm.") carries no URL and no
  // credential verb to trip one. It scored 14 and passed as safe.
  //
  // Retrained on real mail the model reaches 95.5% +/- 1.2%, and on held-out
  // data raising this to 50 cuts misses from 72.8% to 33.2% while the false
  // positive rate does not move (0.92%). The invariant that matters is kept:
  // 50 is still below DANGEROUS_AT, so the model can warn on its own but
  // never convict on its own.
  const maxPull = opts.page?.url ? MODEL_MAX_PULL_PAGE : MODEL_MAX_PULL;
  const modelPull = model.available ? (model.probability - 0.5) * (maxPull * 2) : 0;

  const score = Math.max(0, Math.min(100, ruleScore + modelPull));

  const verdict =
    score >= DANGEROUS_AT ? VERDICT.DANGEROUS : score >= SUSPICIOUS_AT ? VERDICT.SUSPICIOUS : VERDICT.SAFE;

  const reasons = [...heuristics.signals, ...urls.signals, ...impersonation.signals]
    .sort((a, b) => b.weight - a.weight)
    .map((s) => ({ id: s.id, detail: s.detail }));

  return {
    verdict,
    score: Math.round(score),
    reasons,
    exonerating: heuristics.exonerating.map((s) => ({ id: s.id, detail: s.detail })),
    urls: urls.urls,
    model: {
      available: model.available,
      probability: model.probability,
      terms: model.matchedTerms.map((t) => t.term),
    },
    tier: "on-device",
    analyzedAt: new Date().toISOString(),
  };
}

/**
 * True when a second opinion from the cloud tier would actually change
 * something: the local layers landed in the uncertain band, or they convicted
 * on the model alone with no human-readable reason to show.
 */
export function shouldEscalate(local) {
  if (local.score >= ESCALATE_LOW && local.score <= ESCALATE_HIGH) return true;
  if (local.verdict !== VERDICT.SAFE && local.reasons.length === 0) return true;
  return false;
}

/**
 * Full analysis. Runs the local layers, then optionally asks Claude for a
 * reasoned second opinion when a key is configured and the case is uncertain.
 *
 * @param {string} text
 * @param {{sender?: string, source?: string, cloud?: (text, local) => Promise<object|null>}} opts
 */
export async function analyze(text, opts = {}) {
  const local = await analyzeLocal(text, { extraUrls: opts.extraUrls, page: opts.page });
  local.sender = opts.sender || "";
  local.source = opts.source || "manual";

  if (!opts.cloud || !shouldEscalate(local)) return local;

  try {
    const cloud = await opts.cloud(text, local);
    if (!cloud) return local;
    return mergeCloudVerdict(local, cloud);
  } catch (err) {
    // Cloud failures degrade to the local verdict rather than blocking. The
    // user still gets an answer; the error surfaces as a non-blocking note.
    return { ...local, cloudError: err.message };
  }
}

function mergeCloudVerdict(local, cloud) {
  // Claude sees the full message and the local signals, so its verdict wins
  // on direction — but a decisive local rule keeps its floor. We never
  // downgrade a gift-card request to "safe" because a model disagreed.
  const localFloorReasons = local.reasons.length > 0;
  const cloudScore = Math.round(cloud.score);

  let score = cloudScore;
  if (localFloorReasons && local.score >= DANGEROUS_AT) score = Math.max(score, DANGEROUS_AT);

  const verdict =
    score >= DANGEROUS_AT ? VERDICT.DANGEROUS : score >= SUSPICIOUS_AT ? VERDICT.SUSPICIOUS : VERDICT.SAFE;

  return {
    ...local,
    verdict,
    score,
    tier: "claude",
    explanation: cloud.explanation,
    advice: cloud.advice,
    reasons: dedupeReasons([
      ...(cloud.reasons || []).map((detail) => ({ id: "claude", detail })),
      ...local.reasons,
    ]),
  };
}

function dedupeReasons(reasons) {
  const seen = new Set();
  return reasons.filter((r) => {
    const key = r.detail.slice(0, 60).toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export const THRESHOLDS = { DANGEROUS_AT, SUSPICIOUS_AT, ESCALATE_LOW, ESCALATE_HIGH, MODEL_MAX_PULL, MODEL_MAX_PULL_PAGE };
