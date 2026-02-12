/**
 * Middleware Pipeline Runner
 *
 * Executes the middleware chain in order, using a Koa/Express-style
 * compose pattern where each middleware calls next() to pass control.
 */

import type { Middleware, MiddlewareContext, TransactionRequest } from './types.js';

// ---------------------------------------------------------------------------
// C-03 FIX: Address Validation
// ---------------------------------------------------------------------------

/** Regex: 0x followed by exactly 40 hex characters (case-insensitive). */
const ETH_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

/**
 * Validates that a string is a well-formed Ethereum address.
 * Checks: starts with 0x, exactly 42 characters, all hex.
 * Does NOT verify EIP-55 checksum (that's a separate concern).
 */
export function isValidEthereumAddress(address: string): boolean {
  return ETH_ADDRESS_RE.test(address);
}

/**
 * Validates the critical fields of a TransactionRequest.
 * Returns an error message if invalid, or null if valid.
 */
export function validateTransactionRequest(tx: TransactionRequest): string | null {
  // 'to' is required and must be a valid Ethereum address
  if (!tx.to) {
    return 'Transaction is missing the "to" address';
  }
  if (!isValidEthereumAddress(tx.to)) {
    return `Invalid "to" address: "${tx.to}" is not a valid Ethereum address (expected 0x + 40 hex chars)`;
  }

  // chainId must be a positive integer
  if (!Number.isInteger(tx.chainId) || tx.chainId <= 0) {
    return `Invalid chainId: ${tx.chainId}`;
  }

  // value, if present, must be parseable as BigInt
  if (tx.value !== undefined) {
    try {
      const val = BigInt(tx.value);
      if (val < 0n) return 'Transaction value cannot be negative';
    } catch {
      return `Invalid transaction value: "${tx.value}" is not a valid integer`;
    }
  }

  // data, if present, must be a hex string
  if (tx.data !== undefined && tx.data !== '') {
    if (!/^0x[0-9a-fA-F]*$/.test(tx.data)) {
      return `Invalid transaction data: must be a hex string starting with 0x`;
    }
  }

  return null;
}

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
