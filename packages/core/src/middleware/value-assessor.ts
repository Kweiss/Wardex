/**
 * Value Assessor Middleware
 *
 * Calculates the estimated USD value at risk for a transaction.
 * This is critical for tier determination - without it, all transactions
 * fall into the lowest tier.
 *
 * v1: Uses a configurable ETH/USD price (set by operator or fetched at startup).
 *     Does not do real-time price lookups during evaluation (too slow).
 * v2: Will integrate with on-chain price oracles (Chainlink, Uniswap TWAP).
 */

import type { Middleware } from '../types.js';

/**
 * Default ETH price in USD for value estimation.
 * Operators should configure this to a current value.
 * This is deliberately conservative (high) so that transactions
 * are evaluated at a higher tier rather than a lower one.
 */
const DEFAULT_ETH_PRICE_USD = 3500;

export interface ValueAssessorConfig {
  /** Current ETH price in USD. Updated by operator or price feed. */
  ethPriceUsd?: number;
  /** Token prices by contract address (lowercase). Map of address → USD price per token (18 decimals). */
  tokenPricesUsd?: Map<string, number>;
}

/**
 * Creates the value assessor middleware.
 * Populates `ctx.decoded.estimatedValueUsd` for tier determination.
 */
export function createValueAssessor(config?: ValueAssessorConfig): Middleware {
  const ethPrice = config?.ethPriceUsd ?? DEFAULT_ETH_PRICE_USD;
  const tokenPrices = config?.tokenPricesUsd ?? new Map<string, number>();

  return async (ctx, next) => {
    let estimatedValueUsd = 0;

    // 1. Calculate ETH value
    const weiValue = BigInt(ctx.transaction.value ?? '0');
    if (weiValue > 0n) {
      // Convert wei to ETH (1 ETH = 10^18 wei)
      const ethValue = Number(weiValue) / 1e18;
      estimatedValueUsd += ethValue * ethPrice;
    }

    // 2. Calculate token value for approvals and transfers
    if (ctx.decoded) {
      const target = ctx.transaction.to?.toLowerCase();

      if (ctx.decoded.isApproval && ctx.decoded.parameters) {
        const amount = ctx.decoded.parameters.amount;
        if (typeof amount === 'string') {
          try {
            const amountBig = BigInt(amount);
            // Check if this is an infinite approval (max uint256 or > 2^128)
            if (amountBig > BigInt(2) ** BigInt(128)) {
              // For infinite approvals, estimate based on common token balances
              // This is conservative - assume the wallet could have up to $100K
              estimatedValueUsd = Math.max(estimatedValueUsd, 100_000);
            } else if (target && tokenPrices.has(target)) {
              const tokenPrice = tokenPrices.get(target)!;
              const tokenValue = Number(amountBig) / 1e18;
              estimatedValueUsd += tokenValue * tokenPrice;
            }
          } catch {
            // If we can't parse the amount, be conservative
            estimatedValueUsd = Math.max(estimatedValueUsd, 1000);
          }
        }
      }

      if (ctx.decoded.isTransfer && ctx.decoded.parameters) {
        const amount = ctx.decoded.parameters.amount;
        if (typeof amount === 'string' && target && tokenPrices.has(target)) {
          try {
            const amountBig = BigInt(amount);
            const tokenPrice = tokenPrices.get(target)!;
            const tokenValue = Number(amountBig) / 1e18;
            estimatedValueUsd += tokenValue * tokenPrice;
          } catch {
            // Can't parse - use conservative estimate
            estimatedValueUsd = Math.max(estimatedValueUsd, 100);
          }
        }
      }

      // Update the decoded transaction with the value estimate
      ctx.decoded.estimatedValueUsd = estimatedValueUsd;
    }

    // Also store in metadata for other middleware
    ctx.metadata.estimatedValueUsd = estimatedValueUsd;

    await next();
  };
}
