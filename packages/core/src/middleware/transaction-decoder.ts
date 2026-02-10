/**
 * Transaction Decoder Middleware
 *
 * Decodes raw transaction calldata into human-readable information.
 * Identifies function calls, token approvals, transfers, and dangerous patterns.
 */

import type { Middleware, DecodedTransaction, SecurityReason } from '../types.js';

// ---------------------------------------------------------------------------
// Well-known function selectors (first 4 bytes of keccak256 of signature)
// ---------------------------------------------------------------------------

const KNOWN_SELECTORS: Record<string, { name: string; signature: string }> = {
  // ERC-20
  '0xa9059cbb': { name: 'transfer', signature: 'transfer(address,uint256)' },
  '0x23b872dd': { name: 'transferFrom', signature: 'transferFrom(address,address,uint256)' },
  '0x095ea7b3': { name: 'approve', signature: 'approve(address,uint256)' },

  // ERC-721
  '0x42842e0e': { name: 'safeTransferFrom', signature: 'safeTransferFrom(address,address,uint256)' },
  '0xb88d4fde': { name: 'safeTransferFrom', signature: 'safeTransferFrom(address,address,uint256,bytes)' },
  '0xa22cb465': { name: 'setApprovalForAll', signature: 'setApprovalForAll(address,bool)' },

  // Common DeFi
  '0x38ed1739': { name: 'swapExactTokensForTokens', signature: 'swapExactTokensForTokens(uint256,uint256,address[],address,uint256)' },
  '0x7ff36ab5': { name: 'swapExactETHForTokens', signature: 'swapExactETHForTokens(uint256,address[],address,uint256)' },
  '0x18cbafe5': { name: 'swapExactTokensForETH', signature: 'swapExactTokensForETH(uint256,uint256,address[],address,uint256)' },
  '0x5ae401dc': { name: 'multicall', signature: 'multicall(uint256,bytes[])' },
  '0xac9650d8': { name: 'multicall', signature: 'multicall(bytes[])' },

  // ERC-4337
  '0x1fad948c': { name: 'handleOps', signature: 'handleOps(PackedUserOperation[],address)' },

  // Dangerous
  '0x00000000': { name: 'fallback', signature: 'fallback()' },
};

// Maximum uint256 value (infinite approval)
const MAX_UINT256 = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

/**
 * Decodes a 4-byte function selector from calldata.
 */
function decodeSelector(data: string): { name: string; signature: string } | null {
  if (!data || data.length < 10) return null;
  const selector = data.slice(0, 10).toLowerCase();
  return KNOWN_SELECTORS[selector] ?? null;
}

/**
 * Decodes an address from a 32-byte ABI-encoded parameter.
 */
function decodeAddress(param: string): string {
  return '0x' + param.slice(24).toLowerCase();
}

/**
 * Decodes a uint256 from a 32-byte ABI-encoded parameter.
 */
function decodeUint256(param: string): bigint {
  return BigInt('0x' + param);
}

/**
 * Checks if an approval amount is effectively infinite.
 */
function isInfiniteApproval(amountHex: string): boolean {
  // Check for max uint256 or very large values (> 2^128)
  const cleaned = amountHex.replace(/^0x/, '').toLowerCase();
  if (cleaned === MAX_UINT256) return true;
  // Also flag anything over 2^128 as effectively infinite
  try {
    const value = BigInt('0x' + cleaned);
    return value > BigInt(2) ** BigInt(128);
  } catch {
    return false;
  }
}

/**
 * Extracts parameters from ABI-encoded calldata.
 * Returns 32-byte chunks after the 4-byte selector.
 */
function extractParams(data: string): string[] {
  if (!data || data.length <= 10) return [];
  const paramData = data.slice(10);
  const params: string[] = [];
  for (let i = 0; i < paramData.length; i += 64) {
    params.push(paramData.slice(i, i + 64));
  }
  return params;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

export const transactionDecoder: Middleware = async (ctx, next) => {
  const { transaction } = ctx;
  const data = transaction.data ?? '';

  const decoded: DecodedTransaction = {
    raw: transaction,
    isApproval: false,
    isTransfer: false,
    involvesEth: BigInt(transaction.value ?? '0') > 0n,
    estimatedValueUsd: 0, // Will be populated by value assessor middleware
  };

  // Decode function selector
  const selectorInfo = decodeSelector(data);
  if (selectorInfo) {
    decoded.functionName = selectorInfo.name;
  }

  const params = extractParams(data);

  // Identify specific transaction types
  if (selectorInfo) {
    switch (selectorInfo.name) {
      case 'approve': {
        decoded.isApproval = true;
        if (params.length >= 2) {
          const spender = decodeAddress(params[0]);
          const amount = params[1];
          decoded.parameters = {
            spender,
            amount: '0x' + amount,
          };

          if (isInfiniteApproval(amount)) {
            ctx.reasons.push({
              code: 'INFINITE_APPROVAL',
              message: `Infinite token approval detected for spender ${spender}. This allows the spender to drain all tokens of this type from the wallet.`,
              severity: 'critical',
              source: 'transaction',
            });
          }
        }
        break;
      }

      case 'setApprovalForAll': {
        decoded.isApproval = true;
        if (params.length >= 2) {
          const operator = decodeAddress(params[0]);
          const approved = decodeUint256(params[1]) !== 0n;
          decoded.parameters = { operator, approved };

          if (approved) {
            ctx.reasons.push({
              code: 'SET_APPROVAL_FOR_ALL',
              message: `setApprovalForAll grants ${operator} control over ALL NFTs in this collection.`,
              severity: 'high',
              source: 'transaction',
            });
          }
        }
        break;
      }

      case 'transfer': {
        decoded.isTransfer = true;
        if (params.length >= 2) {
          decoded.parameters = {
            to: decodeAddress(params[0]),
            amount: '0x' + params[1],
          };
        }
        break;
      }

      case 'transferFrom': {
        decoded.isTransfer = true;
        if (params.length >= 3) {
          decoded.parameters = {
            from: decodeAddress(params[0]),
            to: decodeAddress(params[1]),
            amount: '0x' + params[2],
          };
        }
        break;
      }

      case 'multicall': {
        // Multicalls can hide malicious operations
        ctx.reasons.push({
          code: 'MULTICALL_DETECTED',
          message: 'Transaction uses multicall - individual operations cannot be fully analyzed in this version',
          severity: 'medium',
          source: 'transaction',
        });
        break;
      }
    }
  }

  // Check for empty data to a contract address (potential fallback function trigger)
  if ((!data || data === '0x') && transaction.to) {
    // This is a plain ETH transfer - generally safe but still needs value assessment
    decoded.isTransfer = true;
    decoded.involvesEth = true;
  }

  // Flag transactions with both value and data (ETH + contract call)
  if (decoded.involvesEth && data && data !== '0x' && data.length > 2) {
    ctx.reasons.push({
      code: 'ETH_WITH_CALLDATA',
      message: 'Transaction sends ETH along with a contract call - verify this is intentional',
      severity: 'low',
      source: 'transaction',
    });
  }

  ctx.decoded = decoded;

  await next();
};
