/**
 * Contract Checker Middleware
 *
 * Analyzes target contract bytecode for dangerous patterns.
 * Wraps the intelligence layer's contract analyzer and contributes
 * findings to the transaction risk score.
 *
 * Runs after the address checker. When intelligence is configured,
 * fetches bytecode via RPC and checks for:
 * - SELFDESTRUCT, DELEGATECALL, CALLCODE opcodes
 * - Proxy patterns (EIP-1167, EIP-1967)
 * - Honeypot indicators
 * - Unverified contract code
 */

import type {
  Middleware,
  ContractAnalysis,
  SecurityReason,
} from '../types.js';

/**
 * Function signature for fetching contract analysis from the intelligence layer.
 */
export type GetContractAnalysis = (
  address: string,
  chainId: number,
) => Promise<ContractAnalysis | null>;

/**
 * Creates the contract checker middleware.
 *
 * @param getContractAnalysis - Function to fetch contract analysis from intelligence.
 *                              If not provided, middleware is a no-op passthrough.
 */
export function createContractChecker(
  getContractAnalysis?: GetContractAnalysis,
): Middleware {
  return async (ctx, next) => {
    // Skip if no intelligence provider or no target address
    if (!getContractAnalysis || !ctx.transaction.to) {
      await next();
      return;
    }

    // Skip if target has calldata that looks like a simple ETH transfer (no data)
    // but still check contracts we're calling into
    const hasCalldata = ctx.transaction.data && ctx.transaction.data !== '0x';
    const hasValue = ctx.transaction.value && BigInt(ctx.transaction.value) > 0n;

    // Only analyze contract if there's calldata (interaction) or it's already known to be a contract
    if (!hasCalldata && !ctx.addressReputation?.labels?.includes('contract')) {
      await next();
      return;
    }

    try {
      const analysis = await getContractAnalysis(
        ctx.transaction.to,
        ctx.transaction.chainId,
      );

      if (!analysis) {
        await next();
        return;
      }

      // Store on context for downstream middleware
      ctx.contractAnalysis = analysis;

      // Generate security reasons from contract analysis
      const reasons: SecurityReason[] = [];

      if (analysis.hasSelfDestruct) {
        reasons.push({
          code: 'CONTRACT_SELFDESTRUCT',
          message: 'Target contract contains SELFDESTRUCT opcode - can be destroyed, potentially losing funds',
          severity: 'critical',
          source: 'contract',
        });
      }

      if (analysis.hasUnsafeDelegatecall && !analysis.isVerified) {
        reasons.push({
          code: 'CONTRACT_UNSAFE_DELEGATECALL',
          message: 'Unverified contract uses DELEGATECALL - can execute arbitrary code',
          severity: 'high',
          source: 'contract',
        });
      }

      if (analysis.isProxy && !analysis.isVerified) {
        reasons.push({
          code: 'CONTRACT_UNVERIFIED_PROXY',
          message: `Contract is a proxy (implementation: ${analysis.implementationAddress ?? 'unknown'}) and source is not verified`,
          severity: 'high',
          source: 'contract',
        });
      }

      if (!analysis.isVerified && analysis.risk !== 'safe') {
        reasons.push({
          code: 'CONTRACT_UNVERIFIED',
          message: 'Contract source code is not verified on block explorer',
          severity: 'medium',
          source: 'contract',
        });
      }

      if (analysis.allowsInfiniteApproval && ctx.decoded?.isApproval) {
        reasons.push({
          code: 'CONTRACT_ALLOWS_INFINITE_APPROVAL',
          message: 'Contract supports unlimited token approvals - ensure amount is limited',
          severity: 'medium',
          source: 'contract',
        });
      }

      for (const pattern of analysis.dangerousPatterns) {
        reasons.push({
          code: `CONTRACT_PATTERN_${pattern.name}`,
          message: pattern.description,
          severity: pattern.severity,
          source: 'contract',
        });
      }

      // Add reasons to context
      ctx.reasons.push(...reasons);

      // Contribute to transaction risk score
      let contractScore = 0;
      for (const reason of reasons) {
        switch (reason.severity) {
          case 'critical': contractScore += 40; break;
          case 'high': contractScore += 25; break;
          case 'medium': contractScore += 10; break;
          case 'low': contractScore += 5; break;
        }
      }

      ctx.riskScores.transaction = Math.min(
        100,
        (ctx.riskScores.transaction ?? 0) + contractScore,
      );
    } catch {
      // Intelligence unavailable - note but don't block
      ctx.reasons.push({
        code: 'CONTRACT_ANALYSIS_UNAVAILABLE',
        message: 'Could not analyze target contract - intelligence layer unavailable',
        severity: 'info',
        source: 'contract',
      });
    }

    await next();
  };
}
