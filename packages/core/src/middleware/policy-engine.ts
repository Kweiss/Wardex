/**
 * Policy Engine Middleware
 *
 * The final middleware in the pipeline. Takes the aggregated risk score and
 * tier determination, and produces the SecurityVerdict decision.
 */

import { randomUUID } from 'node:crypto';
import type { Middleware, SecurityVerdict } from '../types.js';

/**
 * Creates the policy engine middleware.
 * This should be the LAST middleware in the pipeline.
 */
export const policyEngine: Middleware = async (ctx, _next) => {
  const scores = {
    context: ctx.riskScores.context ?? 0,
    transaction: ctx.riskScores.transaction ?? 0,
    behavioral: ctx.riskScores.behavioral ?? 0,
    composite: ctx.riskScores.composite ?? 0,
  };

  const tier = ctx.tier;
  const evaluationId = randomUUID();
  const timestamp = new Date().toISOString();

  // Default verdict
  let decision: SecurityVerdict['decision'] = 'approve';
  let requiredAction: SecurityVerdict['requiredAction'] = 'none';
  let delaySeconds: number | undefined;
  const suggestions: string[] = [];

  if (!tier) {
    // No tier matched - use conservative defaults
    if (scores.composite > 70) {
      decision = 'block';
    } else if (scores.composite > 30) {
      decision = 'advise';
    }
  } else {
    const { enforcement } = tier;

    switch (enforcement.mode) {
      case 'audit':
        // Audit mode: always approve, just log
        decision = 'approve';
        break;

      case 'copilot':
        // Advisory mode: advise on high risk, never block
        if (scores.composite > 50) {
          decision = 'advise';
        } else {
          decision = 'approve';
        }
        break;

      case 'guardian':
        // Guardian mode: block above threshold
        if (scores.composite >= enforcement.blockThreshold) {
          decision = 'block';
          requiredAction = 'human_approval';
        } else if (scores.composite >= enforcement.blockThreshold * 0.6) {
          decision = 'advise';
        } else {
          decision = 'approve';
        }
        break;

      case 'fortress':
        // Fortress mode: always require human approval, add delay
        decision = 'block';
        requiredAction = 'human_approval';
        if (enforcement.timeLockSeconds) {
          requiredAction = 'delay';
          delaySeconds = enforcement.timeLockSeconds;
        }
        break;
    }

    // Override: any critical finding forces a block regardless of tier.
    // This is the "innate immune system" - hard-coded protections that never yield.
    // Only pure audit mode (operator explicitly disabled blocking) is exempt.
    const hasCritical = ctx.reasons.some((r) => r.severity === 'critical');
    if (hasCritical && enforcement.mode !== 'audit') {
      decision = 'block';
      requiredAction = 'human_approval';
    }

    // High-severity context findings (prompt injection, cross-MCP) also force
    // at least an advisory, even in copilot mode
    const hasHighContext = ctx.reasons.some(
      (r) => r.source === 'context' && (r.severity === 'high' || r.severity === 'critical')
    );
    if (hasHighContext && decision === 'approve' && enforcement.mode !== 'audit') {
      decision = 'advise';
    }
  }

  // Check global limits
  const limits = ctx.policy.limits;
  const txValue = BigInt(ctx.transaction.value ?? '0');

  if (txValue > BigInt(limits.maxTransactionValueWei)) {
    decision = 'block';
    requiredAction = 'human_approval';
    ctx.reasons.push({
      code: 'EXCEEDS_TX_LIMIT',
      message: `Transaction value exceeds maximum per-transaction limit`,
      severity: 'high',
      source: 'policy',
    });
  }

  // Generate suggestions for blocked transactions
  if (decision === 'block') {
    if (ctx.reasons.some((r) => r.code === 'INFINITE_APPROVAL')) {
      suggestions.push(
        'Use a specific approval amount instead of infinite approval'
      );
    }
    if (ctx.reasons.some((r) => r.code === 'DENYLISTED_ADDRESS')) {
      suggestions.push(
        'Verify the target address - it appears on known threat lists'
      );
    }
    if (ctx.reasons.some((r) => r.source === 'context')) {
      suggestions.push(
        'Review the conversation context for potential prompt injection'
      );
    }
    if (ctx.reasons.some((r) => r.code === 'NEW_ADDRESS')) {
      suggestions.push(
        'The target address is very new - consider waiting or verifying through an independent channel'
      );
    }
  }

  // Build the verdict
  const verdict: SecurityVerdict = {
    decision,
    riskScore: scores,
    reasons: ctx.reasons,
    suggestions,
    requiredAction,
    delaySeconds,
    timestamp,
    evaluationId,
    tierId: tier?.id ?? 'unknown',
  };

  // Store verdict in metadata for the shield to retrieve
  ctx.metadata.verdict = verdict;
};
