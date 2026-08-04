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

function squash(rawScore) {
  // Map an unbounded positive weight sum onto 0–100 with diminishing returns,
  // so a message with eight weak signals can't outrank one with a single
  // decisive one.
  return 100 * (1 - Math.exp(-rawScore / 2.6));
}

/**
 * Run the local (free, offline, private) layers.
 * @param {string} text
 * @param {{extraUrls?: string[]}} [opts] `extraUrls` carries link targets and
 *   the page address during a whole-page scan — see analyzeUrls.
 * @returns {Promise<object>} verdict object
 */
export async function analyzeLocal(text, opts = {}) {
  const heuristics = analyzeHeuristics(text);
  const urls = analyzeUrls(text, opts.extraUrls || []);

  let model = { probability: 0.5, matchedTerms: [], available: false };
  try {
    model = { ...(await classify(text)), available: true };
  } catch (err) {
    // A missing/corrupt model artifact must not take the whole extension
    // down — the rule layers are the ones that carry the explanations.
    console.warn("[BaitWatch] on-device model unavailable:", err);
  }

  const ruleScore = squash(heuristics.score + urls.score);

  // The model contributes at most ~22 points, and only in the direction it is
  // confident about. It cannot by itself push a message over DANGEROUS.
  const modelPull = model.available ? (model.probability - 0.5) * 44 : 0;

  const score = Math.max(0, Math.min(100, ruleScore + modelPull));

  const verdict =
    score >= DANGEROUS_AT ? VERDICT.DANGEROUS : score >= SUSPICIOUS_AT ? VERDICT.SUSPICIOUS : VERDICT.SAFE;

  const reasons = [...heuristics.signals, ...urls.signals]
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
  const local = await analyzeLocal(text, { extraUrls: opts.extraUrls });
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

export const THRESHOLDS = { DANGEROUS_AT, SUSPICIOUS_AT, ESCALATE_LOW, ESCALATE_HIGH };
