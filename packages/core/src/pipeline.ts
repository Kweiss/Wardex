/**
 * Middleware Pipeline Runner
 *
 * Executes the middleware chain in order, using a Koa/Express-style
 * compose pattern where each middleware calls next() to pass control.
 */

import type { Middleware, MiddlewareContext } from './types.js';

/**
 * Composes an array of middleware into a single function.
 * Each middleware receives a context and a next() function.
 * Calling next() passes control to the next middleware in the chain.
 */
export function compose(middlewares: Middleware[]): Middleware {
  return async (ctx: MiddlewareContext, next: () => Promise<void>) => {
    let index = -1;

    async function dispatch(i: number): Promise<void> {
      if (i <= index) {
        throw new Error('next() called multiple times in the same middleware');
      }
      index = i;

      if (i < middlewares.length) {
        await middlewares[i](ctx, () => dispatch(i + 1));
      } else {
        await next();
      }
    }

    await dispatch(0);
  };
}

/**
 * Creates a fresh middleware context for a new evaluation.
 */
export function createMiddlewareContext(
  overrides: Partial<MiddlewareContext>
): MiddlewareContext {
  return {
    transaction: overrides.transaction ?? {
      to: '',
      chainId: 1,
    },
    conversationContext: overrides.conversationContext,
    riskScores: {},
    reasons: [],
    policy: overrides.policy ?? {
      tiers: [],
      allowlists: { addresses: [], contracts: [], protocols: [] },
      denylists: { addresses: [], patterns: [] },
      limits: {
        maxTransactionValueWei: '0',
        maxDailyVolumeWei: '0',
        maxApprovalAmountWei: '0',
        maxGasPriceGwei: 0,
      },
      behavioral: {
        enabled: false,
        learningPeriodDays: 7,
        sensitivityLevel: 'medium',
      },
      contextAnalysis: {
        enablePromptInjectionDetection: true,
        enableCoherenceChecking: true,
        suspiciousPatterns: [],
        enableEscalationDetection: true,
        enableSourceVerification: true,
      },
    },
    metadata: {},
    ...overrides,
  };
}
