# Security Tiers Reference

Wardex automatically adapts its security posture based on the value at risk. Small transactions pass through quickly; large operations get full scrutiny.

---

## Tier Overview

| Tier | ID | Value Range (USD) | Block Threshold | Human Required | Time Lock | On-Chain Proof |
|---|---|---|---|---|---|---|
| **Audit** | `tier-0-audit` | $0 - $1 | Never (100) | No | No | No |
| **Co-pilot** | `tier-1-copilot` | $1 - $100 | Never (100) | No | No | No |
| **Guardian** | `tier-2-guardian` | $100 - $10,000 | Score > 70 | On block only | No | No |
| **Fortress** | `tier-3-fortress` | > $10,000 | Score > 30 | Always | 15 minutes | Yes |
| **Freeze** | `frozen` | Any | Everything | Required to resume | N/A | N/A |

---

## Tier 0: Audit

**Range**: < $1 USD (gas-only transactions, dust amounts)

| Setting | Value |
|---|---|
| Mode | `audit` |
| Block threshold | 100 (never blocks) |
| Human approval | No |
| Operator notification | No |

**Behavior**: Logs the evaluation but never blocks. Even critical findings (prompt injection, denylisted address) are logged but not acted upon. This is a design choice — blocking dust transactions creates friction without preventing meaningful harm.

**Use case**: Gas-only operations, very small test transactions.

---

## Tier 1: Co-pilot

**Range**: $1 - $100 USD

| Setting | Value |
|---|---|
| Mode | `copilot` |
| Block threshold | 100 (advisory only) |
| Human approval | No |
| Operator notification | No |

**Behavior**: Full evaluation pipeline runs, but the verdict is always `approve` or `advise` — never `block`. Advisory verdicts include risk scores and reasons for operator review, but don't stop the transaction.

**Exception**: Critical findings (denylisted address, prompt injection) in Co-pilot tier are **elevated to block** by the policy engine. The blockThreshold of 100 applies to the composite score, but individual critical findings trigger an override.

**Use case**: Small trades, token swaps, regular DeFi operations.

---

## Tier 2: Guardian

**Range**: $100 - $10,000 USD

| Setting | Value |
|---|---|
| Mode | `guardian` |
| Block threshold | 70 |
| Human approval | On block only |
| Operator notification | Yes |

**Behavior**: Full evaluation pipeline with enforcement. Transactions scoring above 70 are blocked. The operator is notified of all evaluations. Human approval is only required when a transaction is actually blocked (not for every evaluation).

**What gets blocked at this tier**:
- Composite risk score > 70
- Denylisted address (critical finding override)
- Detected prompt injection (critical finding override)
- SELFDESTRUCT contract (critical finding override)
- Unsafe delegatecall (critical finding override)

**Use case**: Medium DeFi operations, token transfers, contract interactions.

---

## Tier 3: Fortress

**Range**: > $10,000 USD

| Setting | Value |
|---|---|
| Mode | `fortress` |
| Block threshold | 30 |
| Human approval | Always |
| Time lock | 900 seconds (15 minutes) |
| Operator notification | Yes |
| On-chain proof | Yes |

**Behavior**: Maximum security. All transactions are blocked first and require explicit human approval. A 15-minute time lock provides a cooling-off period. The evaluation proof hash is recorded for on-chain submission.

**Use case**: Large operations, treasury movements, significant token approvals.

---

## Freeze Mode

**Trigger**: 5 or more blocked transactions in the last 10 evaluations.

When Wardex detects a possible active attack (repeated blocks suggest someone is persistently trying malicious transactions), it automatically freezes all operations.

| Setting | Value |
|---|---|
| All transactions | Blocked with `decision: 'freeze'` |
| Human required | Yes, must call `wardex.unfreeze()` |
| Callbacks | `onFreeze` and `onThreat` fire |

**Recovery**: A human operator must call `wardex.unfreeze()` after investigating.

```typescript
// Automatic freeze fires these callbacks
wardex = createWardex({
  // ...
  onFreeze: (event) => {
    sendAlert(`FROZEN: ${event.reason}`);
  },
});

// Manual freeze
wardex.freeze('Investigating suspicious activity');

// After investigation
wardex.unfreeze();
```

---

## Critical Finding Overrides

Certain findings override the tier's normal block threshold:

| Finding | Override Behavior |
|---|---|
| `DENYLISTED_ADDRESS` | Blocks at Guardian+ regardless of composite score |
| `PROMPT_INJECTION` | Blocks at Guardian+ regardless of composite score |
| `SELFDESTRUCT_DETECTED` | Blocks at Guardian+ regardless of composite score |
| `DELEGATECALL_DETECTED` | Blocks at Guardian+ regardless of composite score |
| `INFINITE_APPROVAL` | Blocks at Guardian+ regardless of composite score |

These overrides do NOT apply at Audit or Co-pilot tiers (by design — dust transactions should not be blocked).

---

## Customizing Tiers

### Change Thresholds

```typescript
const policy = defaultPolicy();

// Fortress at $5K instead of $10K
policy.tiers[3].triggers.minValueAtRiskUsd = 5000;

// Guardian blocks at 50 instead of 70
policy.tiers[2].enforcement.blockThreshold = 50;
```

### Add Protocol-Specific Tiers

```typescript
const uniswapTier: SecurityTierConfig = {
  id: 'uniswap-trading',
  name: 'Uniswap Trading',
  triggers: {
    targetAddresses: ['0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45'],
    maxValueAtRiskUsd: 50_000,
  },
  enforcement: {
    mode: 'guardian',
    blockThreshold: 80,
    requireHumanApproval: false,
    notifyOperator: true,
    requireOnChainProof: false,
  },
};

policy.tiers.splice(3, 0, uniswapTier);
```

### ETH Price Considerations

Tier thresholds are in USD. At different ETH prices, the same amount of ETH falls into different tiers:

| ETH Amount | At $2,000/ETH | At $3,500/ETH | At $5,000/ETH |
|---|---|---|---|
| 0.001 ETH | $2 (Co-pilot) | $3.50 (Co-pilot) | $5 (Co-pilot) |
| 0.05 ETH | $100 (Guardian) | $175 (Guardian) | $250 (Guardian) |
| 1 ETH | $2,000 (Guardian) | $3,500 (Guardian) | $5,000 (Guardian) |
| 5 ETH | $10,000 (Fortress) | $17,500 (Fortress) | $25,000 (Fortress) |

---

## What's Next?

- **[Custom Policies](../guides/custom-policies.md)** — Full policy customization guide
- **[Threat Model](./threat-model.md)** — What Wardex defends against
- **[Attack Vectors](./attack-vectors.md)** — The 7 attack categories
