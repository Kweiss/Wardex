/**
 * Address Checker Middleware
 *
 * Evaluates the target address against allowlists, denylists,
 * and reputation data from the intelligence layer.
 */

import type { Middleware, AddressReputation, SecurityReason } from '../types.js';

/**
 * Normalizes an Ethereum address to lowercase with 0x prefix.
 */
function normalizeAddress(address: string): string {
  return address.toLowerCase().startsWith('0x')
    ? address.toLowerCase()
    : '0x' + address.toLowerCase();
}

/**
 * Creates the address checker middleware.
 *
 * @param getReputation - Optional function to fetch address reputation from intelligence layer.
 *                        If not provided, only allowlist/denylist checks are performed.
 */
export function createAddressChecker(
  getReputation?: (address: string, chainId: number) => Promise<AddressReputation | null>
): Middleware {
  return async (ctx, next) => {
    const { transaction, policy } = ctx;

    if (!transaction.to) {
      // Contract creation transaction
      ctx.reasons.push({
        code: 'CONTRACT_CREATION',
        message: 'Transaction creates a new contract. Ensure this is intentional.',
        severity: 'medium',
        source: 'address',
      });
      await next();
      return;
    }

    const target = normalizeAddress(transaction.to);

    // 1. Check denylist (immediate block)
    const isDenied = policy.denylists.addresses.some(
      (addr) => normalizeAddress(addr) === target
    );
    if (isDenied) {
      ctx.reasons.push({
        code: 'DENYLISTED_ADDRESS',
        message: `Target address ${target} is on the denylist`,
        severity: 'critical',
        source: 'address',
      });
    }

    // 2. Check allowlist (trust boost)
    const isAllowed =
      policy.allowlists.addresses.some(
        (addr) => normalizeAddress(addr) === target
      ) ||
      policy.allowlists.contracts.some(
        (addr) => normalizeAddress(addr) === target
      );

    // 3. Fetch reputation from intelligence layer (if available)
    if (getReputation) {
      try {
        const reputation = await getReputation(target, transaction.chainId);
        if (reputation) {
          ctx.addressReputation = reputation;

          // Flag new addresses (< 7 days old)
          if (reputation.ageDays < 7) {
            ctx.reasons.push({
              code: 'NEW_ADDRESS',
              message: `Target address is only ${reputation.ageDays} day(s) old`,
              severity: 'medium',
              source: 'address',
            });
          }

          // Flag addresses with very low transaction count
          if (reputation.transactionCount < 5 && !isAllowed) {
            ctx.reasons.push({
              code: 'LOW_ACTIVITY_ADDRESS',
              message: `Target address has only ${reputation.transactionCount} transactions`,
              severity: 'low',
              source: 'address',
            });
          }

          // Report risk factors from intelligence
          for (const factor of reputation.riskFactors) {
            ctx.reasons.push({
              code: 'ADDRESS_RISK_FACTOR',
              message: factor,
              severity: 'high',
              source: 'address',
            });
          }
        }
      } catch {
        // Intelligence layer unavailable - note but don't block
        ctx.reasons.push({
          code: 'INTELLIGENCE_UNAVAILABLE',
          message: 'Could not fetch address reputation - intelligence layer unavailable',
          severity: 'info',
          source: 'address',
        });
      }
    }

    // 4. Calculate address risk score
    const addressReasons = ctx.reasons.filter((r) => r.source === 'address');
    let addressScore = 0;

    if (isDenied) {
      addressScore = 100;
    } else if (isAllowed) {
      addressScore = 0;
    } else {
      for (const reason of addressReasons) {
        switch (reason.severity) {
          case 'critical': addressScore += 50; break;
          case 'high': addressScore += 25; break;
          case 'medium': addressScore += 15; break;
          case 'low': addressScore += 5; break;
        }
      }
    }

    // Contribute to transaction risk score
    ctx.riskScores.transaction = Math.min(
      100,
      (ctx.riskScores.transaction ?? 0) + addressScore
    );

    await next();
  };
}
