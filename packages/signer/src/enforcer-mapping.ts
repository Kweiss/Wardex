/**
 * Enforcer Mapping
 *
 * Pure functions that map Wardex SessionKeyConfig fields to MetaMask
 * Delegation Framework caveat enforcer terms. Each enforcer is a smart
 * contract deployed at a canonical address on 35+ EVM chains.
 *
 * The mapping:
 *   allowedContracts   → AllowedTargetsEnforcer
 *   maxValuePerTx      → ValueLteEnforcer
 *   maxDailyVolume     → NativeTokenPeriodTransferEnforcer (period=86400)
 *   durationSeconds    → TimestampEnforcer
 *   forbidInfiniteApprovals → Off-chain (default) or AllowedMethodsEnforcer (strict)
 *
 * All ABI encoding is done manually with ethers.js AbiCoder (already a dep).
 * No dependency on @metamask/delegation-toolkit at runtime.
 *
 * Reference:
 *   https://github.com/metamask/delegation-framework
 *   MetaMask Delegation Toolkit v1.3.0 canonical deployments
 */

import { AbiCoder } from 'ethers';
import type { SessionKeyConfig } from './session-manager.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * A caveat term as expected by the DelegationManager contract.
 * Each caveat specifies an enforcer contract and ABI-encoded terms.
 */
export interface CaveatTerm {
  /** Enforcer contract address */
  enforcer: string;
  /** ABI-encoded terms for this enforcer */
  terms: string;
}

/**
 * Canonical addresses for MetaMask Delegation Framework enforcers.
 * These are the same on all 35+ supported chains (v1.3.0 deployment).
 */
export interface EnforcerAddresses {
  /** AllowedTargetsEnforcer - restricts which contracts can be called */
  allowedTargets: string;
  /** ValueLteEnforcer - caps native value per execution */
  valueLte: string;
  /** NativeTokenPeriodTransferEnforcer - caps native value over a time period */
  nativeTokenPeriodTransfer: string;
  /** TimestampEnforcer - enforces a deadline (after which delegation expires) */
  timestamp: string;
  /** AllowedMethodsEnforcer - restricts which function selectors can be called */
  allowedMethods: string;
  /** LimitedCallsEnforcer - limits total number of calls */
  limitedCalls: string;
  /** AllowedCalldataEnforcer - restricts calldata patterns */
  allowedCalldata: string;
  /** DelegationManager - the core delegation contract */
  delegationManager: string;
}

// ---------------------------------------------------------------------------
// Canonical Addresses (v1.3.0 - same on all supported chains)
// ---------------------------------------------------------------------------

const CANONICAL_ADDRESSES: EnforcerAddresses = {
  allowedTargets: '0x7F20f61b1f09b08D970938F6fa563634d65c4EeB',
  valueLte: '0x92Bf12322527cAA612fd31a0e810472BBB106A8F',
  nativeTokenPeriodTransfer: '0x9BC0FAf4Aca5AE429F4c06aEEaC517520CB16BD9',
  timestamp: '0x1046bb45C8d673d4ea75321280DB34899413c069',
  allowedMethods: '0x6E3eB4b22d7C264FBbb1c25e1d50267136EF4e74',
  limitedCalls: '0x04658B29F6b82ed55274221a06Fc97D318E25416',
  allowedCalldata: '0xc2b0d624c1c4319760C96503BA27C347F3260f55',
  delegationManager: '0xdb9B1e94B5b69Df7e401DDbedE43491141047dB3',
};

// ERC-20 approve(address,uint256) selector
const APPROVE_SELECTOR = '0x095ea7b3';
// ERC-721/1155 setApprovalForAll(address,bool) selector
const SET_APPROVAL_FOR_ALL_SELECTOR = '0xa22cb465';

const coder = new AbiCoder();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Returns the canonical enforcer addresses for MetaMask Delegation Framework v1.3.0.
 */
export function getDefaultEnforcerAddresses(): EnforcerAddresses {
  return { ...CANONICAL_ADDRESSES };
}

/**
 * Maps a Wardex SessionKeyConfig to an array of caveat terms for a delegation.
 *
 * @param config - The session key configuration to map
 * @param addresses - Enforcer contract addresses (defaults to canonical)
 * @param options - Additional options
 * @param options.strictInfiniteApprovalBlocking - If true, adds AllowedMethodsEnforcer
 *        to block approve/setApprovalForAll at the contract level
 * @returns Array of CaveatTerm structs ready for delegation creation
 */
export function mapSessionConfigToCaveats(
  config: SessionKeyConfig,
  addresses: EnforcerAddresses = CANONICAL_ADDRESSES,
  options?: { strictInfiniteApprovalBlocking?: boolean },
): CaveatTerm[] {
  const caveats: CaveatTerm[] = [];

  // 1. AllowedTargetsEnforcer — restrict target contracts
  if (config.allowedContracts.length > 0) {
    caveats.push({
      enforcer: addresses.allowedTargets,
      terms: encodeAllowedTargets(config.allowedContracts),
    });
  }

  // 2. ValueLteEnforcer — cap native value per execution
  if (config.maxValuePerTx && BigInt(config.maxValuePerTx) > 0n) {
    caveats.push({
      enforcer: addresses.valueLte,
      terms: encodeValueLte(config.maxValuePerTx),
    });
  }

  // 3. NativeTokenPeriodTransferEnforcer — cap daily volume
  if (config.maxDailyVolume && BigInt(config.maxDailyVolume) > 0n) {
    caveats.push({
      enforcer: addresses.nativeTokenPeriodTransfer,
      terms: encodeNativeTokenPeriod(config.maxDailyVolume, 86400), // 24h period
    });
  }

  // 4. TimestampEnforcer — set expiration deadline
  if (config.durationSeconds > 0) {
    caveats.push({
      enforcer: addresses.timestamp,
      terms: encodeTimestamp(config.durationSeconds),
    });
  }

  // 5. AllowedMethodsEnforcer — block approve/setApprovalForAll (strict mode only)
  if (config.forbidInfiniteApprovals && options?.strictInfiniteApprovalBlocking) {
    caveats.push({
      enforcer: addresses.allowedMethods,
      terms: encodeBlockedApprovalMethods(),
    });
  }

  return caveats;
}

// ---------------------------------------------------------------------------
// Encoding Functions
// ---------------------------------------------------------------------------

/**
 * ABI-encodes the terms for AllowedTargetsEnforcer.
 * Format: abi.encode(address[])
 *
 * @param contracts - Array of allowed contract addresses
 * @returns Hex-encoded terms
 */
export function encodeAllowedTargets(contracts: string[]): string {
  const normalized = contracts.map((c) => c.toLowerCase());
  return coder.encode(['address[]'], [normalized]);
}

/**
 * ABI-encodes the terms for ValueLteEnforcer.
 * Format: abi.encode(uint256) — the maximum native value in wei
 *
 * @param maxWei - Maximum value in wei (as string for BigInt compat)
 * @returns Hex-encoded terms
 */
export function encodeValueLte(maxWei: string): string {
  return coder.encode(['uint256'], [BigInt(maxWei)]);
}

/**
 * ABI-encodes the terms for TimestampEnforcer.
 * Format: abi.encode(uint256, uint256) — (afterTimestamp, beforeTimestamp)
 * We set afterTimestamp=0 (no start constraint) and beforeTimestamp=now+duration.
 *
 * @param durationSeconds - Duration from now until expiry
 * @returns Hex-encoded terms
 */
export function encodeTimestamp(durationSeconds: number): string {
  const afterTimestamp = 0n; // No "not before" constraint
  const beforeTimestamp = BigInt(Math.floor(Date.now() / 1000) + durationSeconds);
  return coder.encode(['uint256', 'uint256'], [afterTimestamp, beforeTimestamp]);
}

/**
 * ABI-encodes the terms for NativeTokenPeriodTransferEnforcer.
 * Format: abi.encode(uint256, uint256) — (allowance, period)
 *
 * @param maxWei - Maximum native token transfer in the period (wei string)
 * @param periodSeconds - Period length in seconds (default: 86400 = 24h)
 * @returns Hex-encoded terms
 */
export function encodeNativeTokenPeriod(
  maxWei: string,
  periodSeconds: number = 86400,
): string {
  return coder.encode(
    ['uint256', 'uint256'],
    [BigInt(maxWei), BigInt(periodSeconds)],
  );
}

/**
 * ABI-encodes the terms for AllowedMethodsEnforcer to block
 * approve(address,uint256) and setApprovalForAll(address,bool).
 *
 * The AllowedMethodsEnforcer uses a whitelist of allowed selectors.
 * We encode an empty array to block ALL function calls, then rely on
 * the fact that the agent should only do transfers/swaps (not approvals).
 *
 * Actually, AllowedMethodsEnforcer works as an allowlist: only listed
 * selectors are permitted. We list common safe selectors and exclude
 * approve/setApprovalForAll.
 *
 * For strict mode, we encode just the common DeFi selectors:
 *   - transfer(address,uint256)        = 0xa9059cbb
 *   - transferFrom(address,address,uint256) = 0x23b872dd
 *   - swapExactTokensForTokens         = 0x38ed1739
 *   - swapTokensForExactTokens         = 0x8803dbee
 *   - multicall(uint256,bytes[])       = 0x5ae401dc
 *
 * @returns Hex-encoded terms (array of 4-byte selectors)
 */
export function encodeBlockedApprovalMethods(): string {
  // Allowed selectors (approve and setApprovalForAll are excluded)
  const allowedSelectors = [
    '0xa9059cbb', // transfer(address,uint256)
    '0x23b872dd', // transferFrom(address,address,uint256)
    '0x38ed1739', // swapExactTokensForTokens
    '0x8803dbee', // swapTokensForExactTokens
    '0x5ae401dc', // multicall(uint256,bytes[])
  ];

  return coder.encode(['bytes4[]'], [allowedSelectors]);
}

// ---------------------------------------------------------------------------
// Decoding / Inspection Helpers
// ---------------------------------------------------------------------------

/**
 * Decodes AllowedTargets terms back into an array of addresses.
 * Useful for inspecting existing delegations.
 */
export function decodeAllowedTargets(terms: string): string[] {
  const [addresses] = coder.decode(['address[]'], terms);
  return (addresses as string[]).map((a: string) => a.toLowerCase());
}

/**
 * Decodes ValueLte terms back into a max value (wei string).
 */
export function decodeValueLte(terms: string): string {
  const [maxValue] = coder.decode(['uint256'], terms);
  return (maxValue as bigint).toString();
}

/**
 * Decodes Timestamp terms back into (afterTimestamp, beforeTimestamp).
 */
export function decodeTimestamp(terms: string): {
  afterTimestamp: number;
  beforeTimestamp: number;
} {
  const [after, before] = coder.decode(['uint256', 'uint256'], terms);
  return {
    afterTimestamp: Number(after as bigint),
    beforeTimestamp: Number(before as bigint),
  };
}

/**
 * Decodes NativeTokenPeriodTransfer terms back into (allowance, period).
 */
export function decodeNativeTokenPeriod(terms: string): {
  allowance: string;
  periodSeconds: number;
} {
  const [allowance, period] = coder.decode(['uint256', 'uint256'], terms);
  return {
    allowance: (allowance as bigint).toString(),
    periodSeconds: Number(period as bigint),
  };
}
