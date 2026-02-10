/**
 * Risk Aggregator Middleware
 *
 * Combines risk scores from all previous middleware into a composite score.
 * Determines which security tier applies and produces the final risk assessment.
 */

import type {
  Middleware,
  RiskScore,
  SecurityTierConfig,
  SecurityPolicy,
} from '../types.js';

/**
 * Default risk score weights.
 * Context (prompt injection) is weighted highest because it represents
 * compromised decision-making, which is the most dangerous scenario.
 */
const DEFAULT_WEIGHTS = {
  context: 0.40,
  transaction: 0.35,
  behavioral: 0.25,
};

/**
 * Determines which security tier applies to a transaction based on
 * its estimated USD value and other trigger conditions.
 */
function determineTier(
  policy: SecurityPolicy,
  estimatedValueUsd: number,
  targetAddress?: string,
  functionSignature?: string
): SecurityTierConfig | undefined {
  // Sort tiers by minValueAtRiskUsd descending so we match the highest applicable tier
  const sortedTiers = [...policy.tiers].sort(
    (a, b) =>
      (b.triggers.minValueAtRiskUsd ?? 0) - (a.triggers.minValueAtRiskUsd ?? 0)
  );

  for (const tier of sortedTiers) {
    const { triggers } = tier;

    // Check address-specific triggers first (they override value-based tiers)
    if (
      triggers.targetAddresses &&
      targetAddress &&
      triggers.targetAddresses.some(
        (a) => a.toLowerCase() === targetAddress.toLowerCase()
      )
    ) {
      return tier;
    }

    // Check function signature triggers
    if (
      triggers.functionSignatures &&
      functionSignature &&
      triggers.functionSignatures.includes(functionSignature)
    ) {
      return tier;
    }

    // Check value-based triggers
    const minValue = triggers.minValueAtRiskUsd ?? 0;
    const maxValue = triggers.maxValueAtRiskUsd ?? Infinity;

    if (estimatedValueUsd >= minValue && estimatedValueUsd < maxValue) {
      return tier;
    }
  }

  // Default to the lowest tier if no match
  return sortedTiers[sortedTiers.length - 1];
}

/**
 * Creates the risk aggregator middleware.
 */
export const riskAggregator: Middleware = async (ctx, next) => {
  // Fill in any missing risk scores with 0
  const scores: RiskScore = {
    context: ctx.riskScores.context ?? 0,
    transaction: ctx.riskScores.transaction ?? 0,
    behavioral: ctx.riskScores.behavioral ?? 0,
    composite: 0,
  };

  // Calculate weighted composite score
  scores.composite = Math.round(
    scores.context * DEFAULT_WEIGHTS.context +
    scores.transaction * DEFAULT_WEIGHTS.transaction +
    scores.behavioral * DEFAULT_WEIGHTS.behavioral
  );

  // Clamp to 0-100
  scores.composite = Math.max(0, Math.min(100, scores.composite));

  // Override: if any single score is critical (>= 90), composite is at least 80
  if (scores.context >= 90 || scores.transaction >= 90 || scores.behavioral >= 90) {
    scores.composite = Math.max(scores.composite, 80);
  }

  ctx.riskScores = scores;

  // Determine applicable security tier
  const estimatedValue = ctx.decoded?.estimatedValueUsd ?? 0;
  const tier = determineTier(
    ctx.policy,
    estimatedValue,
    ctx.transaction.to,
    ctx.decoded?.functionName
  );

  if (tier) {
    ctx.tier = tier;
  }

  await next();
};
