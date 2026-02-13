import { describe, it, expect } from 'vitest';
import { createWardex, defaultPolicy } from '@wardexai/core';
import type { SecurityTierConfig, SecurityPolicy, TransactionRequest } from '@wardexai/core';

const LOW_VALUE_ADDRESS = '0x1111111111111111111111111111111111111111';
const SPECIAL_ADDRESS = '0x2222222222222222222222222222222222222222';
const TOKEN_ADDRESS = '0x3333333333333333333333333333333333333333';

function makeTier(
  id: string,
  mode: 'audit' | 'copilot' | 'guardian' | 'fortress',
  minValueAtRiskUsd?: number,
  maxValueAtRiskUsd?: number,
  extra?: Partial<SecurityTierConfig['triggers']>
): SecurityTierConfig {
  return {
    id,
    name: id,
    triggers: {
      minValueAtRiskUsd,
      maxValueAtRiskUsd,
      ...extra,
    },
    enforcement: {
      mode,
      blockThreshold: mode === 'fortress' ? 30 : mode === 'guardian' ? 70 : 100,
      requireHumanApproval: mode === 'fortress',
      notifyOperator: mode === 'guardian' || mode === 'fortress',
      requireOnChainProof: mode === 'fortress',
      timeLockSeconds: mode === 'fortress' ? 900 : undefined,
    },
  };
}

function createCustomWardex(tiers: SecurityTierConfig[]) {
  const policy: SecurityPolicy = {
    ...defaultPolicy(),
    tiers,
  };

  return createWardex({
    policy,
    signer: { type: 'isolated-process', endpoint: '/tmp/risk-tiering-test.sock' },
    mode: 'adaptive',
  });
}

describe('Risk Tiering Calibration', () => {
  it('should use the upper tier when value is exactly at a min boundary', async () => {
    const tiers: SecurityTierConfig[] = [
      makeTier('tier-audit', 'audit', 0, 3500),
      makeTier('tier-copilot', 'copilot', 3500, 7000),
      makeTier('tier-guardian', 'guardian', 7000),
    ];

    const wardex = createCustomWardex(tiers);

    const tx: TransactionRequest = {
      to: LOW_VALUE_ADDRESS,
      value: '1000000000000000000', // 1 ETH ~= $3500 by default assessor
      chainId: 1,
    };

    const verdict = await wardex.evaluate(tx);

    expect(verdict.tierId).toBe('tier-copilot');
  });

  it('should prioritize targetAddress trigger over value-based tiering', async () => {
    const tiers: SecurityTierConfig[] = [
      makeTier('tier-audit', 'audit', 0, 1000),
      makeTier('tier-guardian', 'guardian', 1000),
      makeTier('tier-address-override', 'fortress', 999999, undefined, {
        targetAddresses: [SPECIAL_ADDRESS],
      }),
    ];

    const wardex = createCustomWardex(tiers);

    const tx: TransactionRequest = {
      to: SPECIAL_ADDRESS,
      value: '100000000000000', // low value, would normally map to audit
      chainId: 1,
    };

    const verdict = await wardex.evaluate(tx);

    expect(verdict.tierId).toBe('tier-address-override');
  });

  it('should prioritize function trigger over value-based tiering', async () => {
    const tiers: SecurityTierConfig[] = [
      makeTier('tier-audit', 'audit', 0, 1000),
      makeTier('tier-guardian', 'guardian', 1000),
      makeTier('tier-function-override', 'guardian', 999999, undefined, {
        functionSignatures: ['approve'],
      }),
    ];

    const wardex = createCustomWardex(tiers);

    const approveCalldata =
      '0x095ea7b3' +
      '000000000000000000000000' +
      LOW_VALUE_ADDRESS.slice(2) +
      '0000000000000000000000000000000000000000000000000000000000000001';

    const tx: TransactionRequest = {
      to: TOKEN_ADDRESS,
      value: '0',
      data: approveCalldata,
      chainId: 1,
    };

    const verdict = await wardex.evaluate(tx);

    expect(verdict.tierId).toBe('tier-function-override');
  });
});
