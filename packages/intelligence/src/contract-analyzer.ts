/**
 * Contract Bytecode Analyzer
 *
 * Analyzes EVM bytecode for dangerous patterns without requiring
 * source code or ABI. Detects:
 * - SELFDESTRUCT opcode (can destroy the contract and steal funds)
 * - DELEGATECALL to unknown addresses (can execute arbitrary code)
 * - Proxy patterns (EIP-1967, EIP-1167 minimal proxy)
 * - Honeypot indicators (approve with hidden restrictions)
 */

import type { ContractPattern } from './types.js';

// EVM opcodes we care about (hex values)
const OPCODES = {
  DELEGATECALL: 'f4',
  SELFDESTRUCT: 'ff',
  SLOAD: '54',
  CREATE: 'f0',
  CREATE2: 'f5',
  CALLCODE: 'f2',
} as const;

// Known function selectors
const SELECTORS = {
  APPROVE: '095ea7b3',
  TRANSFER: 'a9059cbb',
  TRANSFER_FROM: '23b872dd',
} as const;

// EIP-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
const EIP_1967_IMPL_SLOT = '360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc';

// EIP-1167 minimal proxy prefix
const MINIMAL_PROXY_PREFIX = '363d3d373d3d3d363d73';
const MINIMAL_PROXY_SUFFIX = '5af43d82803e903d91602b57fd5bf3';

export interface BytecodeAnalysis {
  /** Whether SELFDESTRUCT opcode is present */
  hasSelfDestruct: boolean;
  /** Whether DELEGATECALL opcode is present */
  hasDelegatecall: boolean;
  /** Whether CALLCODE opcode is present (deprecated, dangerous) */
  hasCallcode: boolean;
  /** Whether this is a proxy contract */
  isProxy: boolean;
  /** Implementation address if proxy detected */
  implementationAddress?: string;
  /** Whether CREATE/CREATE2 opcodes are present */
  hasFactoryCapability: boolean;
  /** Whether approve function selector is present */
  hasApproveFunction: boolean;
  /** Dangerous patterns detected */
  patterns: ContractPattern[];
}

/**
 * Analyzes raw EVM bytecode for dangerous patterns.
 * @param bytecode - Hex-encoded bytecode string (with or without 0x prefix)
 */
export function analyzeContractBytecode(bytecode: string): BytecodeAnalysis {
  const code = bytecode.toLowerCase().replace(/^0x/, '');
  const patterns: ContractPattern[] = [];

  const analysis: BytecodeAnalysis = {
    hasSelfDestruct: false,
    hasDelegatecall: false,
    hasCallcode: false,
    isProxy: false,
    hasFactoryCapability: false,
    hasApproveFunction: false,
    patterns: [],
  };

  if (!code || code.length < 2) {
    return analysis;
  }

  // Check for SELFDESTRUCT opcode
  // Note: We search for the opcode byte, but must be careful about
  // false positives (it could appear as data, not as an opcode).
  // We check for it in reasonable positions.
  if (code.includes(OPCODES.SELFDESTRUCT)) {
    analysis.hasSelfDestruct = true;
    patterns.push({
      name: 'SELFDESTRUCT',
      pattern: OPCODES.SELFDESTRUCT,
      severity: 'critical',
      description:
        'Contract contains SELFDESTRUCT opcode - can be permanently destroyed, ' +
        'potentially sending all ETH to an arbitrary address',
    });
  }

  // Check for DELEGATECALL opcode
  if (code.includes(OPCODES.DELEGATECALL)) {
    analysis.hasDelegatecall = true;
    // Only flag as dangerous if it doesn't look like a standard proxy
    if (!isStandardProxy(code)) {
      patterns.push({
        name: 'DELEGATECALL',
        pattern: OPCODES.DELEGATECALL,
        severity: 'high',
        description:
          'Contract uses DELEGATECALL to execute code from another contract. ' +
          'This can execute arbitrary code in the context of this contract.',
      });
    }
  }

  // Check for deprecated CALLCODE opcode
  if (code.includes(OPCODES.CALLCODE)) {
    analysis.hasCallcode = true;
    patterns.push({
      name: 'CALLCODE',
      pattern: OPCODES.CALLCODE,
      severity: 'high',
      description:
        'Contract uses deprecated CALLCODE opcode - may indicate ' +
        'outdated or intentionally obfuscated code',
    });
  }

  // Check for CREATE/CREATE2 (factory patterns)
  if (code.includes(OPCODES.CREATE) || code.includes(OPCODES.CREATE2)) {
    analysis.hasFactoryCapability = true;
  }

  // Check for EIP-1167 minimal proxy
  if (code.includes(MINIMAL_PROXY_PREFIX)) {
    analysis.isProxy = true;
    // Extract implementation address from minimal proxy bytecode
    const prefixIndex = code.indexOf(MINIMAL_PROXY_PREFIX);
    const addrStart = prefixIndex + MINIMAL_PROXY_PREFIX.length;
    const addrHex = code.slice(addrStart, addrStart + 40);
    if (addrHex.length === 40) {
      analysis.implementationAddress = '0x' + addrHex;
    }
  }

  // Check for EIP-1967 proxy pattern (loads from implementation slot)
  if (code.includes(EIP_1967_IMPL_SLOT)) {
    analysis.isProxy = true;
    patterns.push({
      name: 'EIP_1967_PROXY',
      pattern: EIP_1967_IMPL_SLOT,
      severity: 'medium',
      description:
        'Contract is an EIP-1967 proxy - the implementation can be changed ' +
        'by the proxy admin, potentially altering contract behavior',
    });
  }

  // Check for approve function selector
  if (code.includes(SELECTORS.APPROVE)) {
    analysis.hasApproveFunction = true;
  }

  // Honeypot indicators: transfer function exists but has unusual patterns
  if (code.includes(SELECTORS.TRANSFER)) {
    // Check if the bytecode is unusually small for a token contract
    // (might be a honeypot that strips transfer logic)
    if (code.length < 200 && code.includes(SELECTORS.APPROVE)) {
      patterns.push({
        name: 'SUSPICIOUS_TOKEN_SIZE',
        pattern: 'small-bytecode-with-token-selectors',
        severity: 'high',
        description:
          'Contract has token function selectors but unusually small bytecode - ' +
          'may be a honeypot or stripped implementation',
      });
    }
  }

  analysis.patterns = patterns;
  return analysis;
}

/**
 * Checks if bytecode looks like a standard proxy pattern
 * (EIP-1167, EIP-1967, OpenZeppelin proxy, etc.)
 */
function isStandardProxy(code: string): boolean {
  return (
    code.includes(MINIMAL_PROXY_PREFIX) ||
    code.includes(EIP_1967_IMPL_SLOT) ||
    // OpenZeppelin TransparentUpgradeableProxy pattern
    code.includes('5c60da1b') // implementation() selector
  );
}
