import { describe, it, expect } from 'vitest';
import { createWardex, defaultPolicy } from '@wardexai/core';
import type { SecurityPolicy } from '@wardexai/core';

function createTestWardex(policyOverrides?: Partial<SecurityPolicy>) {
  const policy = defaultPolicy();
  if (policyOverrides) {
    Object.assign(policy, policyOverrides);
  }
  return createWardex({
    policy,
    signer: { type: 'isolated-process', endpoint: '/tmp/test-signer.sock' },
    mode: 'adaptive',
  });
}

describe('Policy Guardrails', () => {
  it('should reject empty tier override', () => {
    const wardex = createTestWardex();
    expect(() => wardex.updatePolicy({ tiers: [] })).toThrow(/at least one security tier/i);
  });

  it('should reject tier overrides without guardian/fortress blocking tiers', () => {
    const wardex = createTestWardex();
    const nonBlockingTiers = [
      {
        id: 'audit-only',
        name: 'Audit Only',
        triggers: { minValueAtRiskUsd: 0 },
        enforcement: {
          mode: 'audit' as const,
          blockThreshold: 100,
          requireHumanApproval: false,
          notifyOperator: false,
          requireOnChainProof: false,
        },
      },
    ];

    expect(() => wardex.updatePolicy({ tiers: nonBlockingTiers })).toThrow(/blocking tier/i);
  });

  it('should prevent custom middleware from mutating nested policy structures', async () => {
    const wardex = createTestWardex();

    wardex.use(async (ctx, next) => {
      // This would mutate the live policy if sandboxing is shallow.
      let mutationFailed = false;
      try {
        ctx.policy.denylists.addresses.push(ctx.transaction.to);
      } catch {
        mutationFailed = true;
      }
      expect(mutationFailed).toBe(true);
      await next();
    });

    const tx = {
      to: '0x1111111111111111111111111111111111111111',
      value: '1',
      chainId: 1,
    };

    const verdict1 = await wardex.evaluate(tx);
    expect(verdict1.reasons.some((r) => r.code === 'PIPELINE_ERROR')).toBe(false);

    // Run again to ensure denylist was not persistently mutated by middleware.
    const verdict2 = await wardex.evaluate(tx);
    expect(verdict2.reasons.some((r) => r.code === 'DENYLISTED_ADDRESS')).toBe(false);
  });

  it('should block custom middleware from tampering with downstream verdicts', async () => {
    const wardex = createTestWardex();

    wardex.use(async (ctx, next) => {
      await next();
      ctx.metadata.verdict = {
        decision: 'block',
        riskScore: { context: 0, transaction: 0, behavioral: 0, composite: 100 },
        reasons: [],
        suggestions: [],
        timestamp: new Date().toISOString(),
        evaluationId: 'tampered',
        tierId: 'tampered',
      };
    });

    const tx = {
      to: '0x1111111111111111111111111111111111111111',
      value: '1',
      chainId: 1,
    };

    const verdict = await wardex.evaluate(tx);
    expect(verdict.evaluationId).not.toBe('tampered');
    expect(verdict.reasons.some((r) => r.code === 'MIDDLEWARE_VERDICT_TAMPER_BLOCKED')).toBe(true);
  });
});
