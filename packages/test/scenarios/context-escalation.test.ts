import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createWardex, defaultPolicy } from '@wardexai/core';
import type { ConversationContext, TransactionRequest } from '@wardexai/core';

const TARGET = '0x1111111111111111111111111111111111111111';

function createTestWardex() {
  return createWardex({
    policy: defaultPolicy(),
    signer: { type: 'isolated-process', endpoint: '/tmp/context-escalation.sock' },
    mode: 'adaptive',
  });
}

function context(): ConversationContext {
  return {
    messages: [
      { role: 'user', content: 'Please transfer ETH for this payment flow.' },
    ],
    source: {
      type: 'user',
      identifier: 'direct',
      trustLevel: 'high',
    },
  };
}

async function evaluateWithEth(wardex: ReturnType<typeof createTestWardex>, eth: number) {
  const wei = BigInt(Math.floor(eth * 1e6)) * 10n ** 12n;
  const tx: TransactionRequest = {
    to: TARGET,
    value: wei.toString(),
    chainId: 1,
  };
  return wardex.evaluateWithContext(tx, context());
}

describe('Context Analyzer - Escalation Thresholds', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-02-13T00:00:00.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should flag VALUE_ESCALATION at exactly 5x within 30 minutes', async () => {
    const wardex = createTestWardex();

    await evaluateWithEth(wardex, 0.01); // baseline
    vi.advanceTimersByTime(5 * 60 * 1000);
    const verdict = await evaluateWithEth(wardex, 0.05); // 5x

    expect(verdict.reasons.some((r) => r.code === 'VALUE_ESCALATION')).toBe(true);
  });

  it('should not flag VALUE_ESCALATION below 5x', async () => {
    const wardex = createTestWardex();

    await evaluateWithEth(wardex, 0.01);
    vi.advanceTimersByTime(5 * 60 * 1000);
    const verdict = await evaluateWithEth(wardex, 0.049); // 4.9x

    expect(verdict.reasons.some((r) => r.code === 'VALUE_ESCALATION')).toBe(false);
  });

  it('should not flag VALUE_ESCALATION when increase is outside 30-minute window', async () => {
    const wardex = createTestWardex();

    await evaluateWithEth(wardex, 0.01);
    vi.advanceTimersByTime(31 * 60 * 1000);
    const verdict = await evaluateWithEth(wardex, 0.2); // 20x but outside window

    expect(verdict.reasons.some((r) => r.code === 'VALUE_ESCALATION')).toBe(false);
  });
});
