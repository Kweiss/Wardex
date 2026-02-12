# Audit Trail & Compliance

Wardex records every security evaluation in an audit trail. This provides full accountability, incident response capabilities, and compliance evidence.

---

## What Gets Logged

Every call to `evaluate()` or `evaluateWithContext()` produces an audit entry:

```typescript
interface AuditEntry {
  evaluationId: string;          // Unique ID (UUID v4)
  timestamp: string;             // ISO 8601 timestamp
  transaction: TransactionRequest; // The transaction that was evaluated
  verdict: SecurityVerdict;      // Full verdict with scores and reasons
  contextSummary?: string;       // Sanitized context summary (no sensitive data)
  executed: boolean;             // Whether the transaction was ultimately executed
}
```

**What is NOT logged**:
- Private keys or seed phrases (impossible — output filter catches these)
- Raw conversation content (only a summary: "3 messages, source: user-cli")
- Signer credentials or approval tokens

---

## Accessing the Audit Log

### Read the Full Log

```typescript
const entries = wardex.getAuditLog();
// Returns all entries (up to 10,000 most recent)
```

### Read Recent Entries

```typescript
const recent = wardex.getAuditLog(50);
// Returns the last 50 entries
```

### Query by Decision

```typescript
const blocked = wardex.getAuditLog()
  .filter(e => e.verdict.decision === 'block');

const frozen = wardex.getAuditLog()
  .filter(e => e.verdict.decision === 'freeze');
```

### Query by Time Range

```typescript
const lastHour = wardex.getAuditLog()
  .filter(e => new Date(e.timestamp) > new Date(Date.now() - 3600_000));
```

### Query by Risk Score

```typescript
const highRisk = wardex.getAuditLog()
  .filter(e => e.verdict.riskScore.composite > 50);
```

---

## Audit Entry Details

Each entry contains the full verdict, which includes:

| Field | Description | Use |
|---|---|---|
| `evaluationId` | Unique UUID for this evaluation | Correlation across systems |
| `timestamp` | ISO 8601 timestamp | Timeline reconstruction |
| `transaction.to` | Target address | Identify counterparties |
| `transaction.value` | Wei value | Track fund flows |
| `verdict.decision` | approve / advise / block / freeze | Action taken |
| `verdict.riskScore` | Component scores (0-100) | Risk trend analysis |
| `verdict.reasons` | Array of findings | Root cause analysis |
| `verdict.tierId` | Which security tier applied | Policy audit |
| `verdict.proofHash` | Evaluation hash | On-chain submission |
| `executed` | Whether tx was executed | Completion tracking |

---

## Event Callbacks

In addition to the audit log, Wardex fires real-time callbacks:

```typescript
const wardex = createWardex({
  policy,
  signer: { type: 'isolated-process', endpoint: '/tmp/wardex.sock' },
  mode: 'adaptive',

  onBlock: (event) => {
    // Fired when a transaction is blocked
    log.warn('Transaction blocked', {
      evaluationId: event.verdict.evaluationId,
      to: event.transaction.to,
      reasons: event.verdict.reasons.map(r => r.code),
    });
  },

  onAdvisory: (event) => {
    // Fired when an advisory is issued
    log.info('Advisory issued', {
      evaluationId: event.verdict.evaluationId,
      riskScore: event.verdict.riskScore.composite,
    });
  },

  onThreat: (event) => {
    // Fired when a threat is detected (may or may not block)
    alerting.send({
      type: event.threatType,
      severity: event.severity,
      details: event.details,
    });
  },

  onFreeze: (event) => {
    // Fired when auto-freeze triggers or manual freeze is called
    pager.alert({
      message: `WARDEX FROZEN: ${event.reason}`,
      timestamp: event.timestamp,
    });
  },
});
```

---

## On-Chain Proof Submission

For Fortress-tier evaluations, the verdict includes a `proofHash` that can be submitted on-chain:

```typescript
const verdict = await wardex.evaluate(tx);

if (verdict.proofHash) {
  // Submit to WardexValidationModule for on-chain audit
  // This provides tamper-proof evidence of the security evaluation
  console.log(`Proof hash: ${verdict.proofHash}`);
}
```

The proof hash is a cryptographic hash of:
- Transaction details (to, value, data, chainId)
- Risk scores
- Decision
- Timestamp
- Evaluation ID

This enables verifiable audit trails that cannot be retroactively modified.

---

## Log Retention

| Setting | Value |
|---|---|
| In-memory retention | Last 10,000 entries |
| Rotation | FIFO — oldest entries dropped when limit reached |
| Persistence | Not built-in (use callbacks to export) |

### Exporting to External Storage

```typescript
// Export to a file every hour
setInterval(() => {
  const entries = wardex.getAuditLog();
  fs.appendFileSync(
    '/var/log/wardex-audit.jsonl',
    entries.map(e => JSON.stringify(e)).join('\n') + '\n'
  );
}, 3600_000);
```

```typescript
// Stream to a monitoring service via callbacks
const wardex = createWardex({
  // ...
  onBlock: (event) => {
    monitoringService.trackEvent('wardex.block', {
      evaluationId: event.verdict.evaluationId,
      decision: event.verdict.decision,
      riskScore: event.verdict.riskScore.composite,
      reasons: event.verdict.reasons,
      timestamp: event.verdict.timestamp,
    });
  },
});
```

---

## Compliance Use Cases

### Incident Response

When a security incident occurs, the audit trail provides:

1. **Timeline**: Exact sequence of evaluations leading up to the incident
2. **Root cause**: Which findings triggered blocks vs. approvals
3. **Scope**: All transactions that passed through during the time window
4. **Evidence**: Immutable evaluation IDs and proof hashes

```typescript
// Reconstruct the last 24 hours of activity
const recentLog = wardex.getAuditLog()
  .filter(e => new Date(e.timestamp) > new Date(Date.now() - 86400_000));

const timeline = recentLog.map(e => ({
  time: e.timestamp,
  decision: e.verdict.decision,
  to: e.transaction.to,
  value: e.transaction.value,
  riskScore: e.verdict.riskScore.composite,
  topReason: e.verdict.reasons[0]?.code,
}));
```

### Regulatory Reporting

For regulated entities, the audit trail demonstrates:

- **Due diligence**: Every transaction was evaluated against a defined policy
- **Risk management**: Risk scores and tier assignments are documented
- **Access control**: Key isolation ensures separation of duties
- **Anomaly detection**: Behavioral monitoring provides ongoing surveillance

### Security Audits

For external security audits:

- **Policy documentation**: `defaultPolicy()` output shows the baseline rules
- **Test coverage**: 168 tests across 12 suites verify all detection mechanisms
- **Evaluation history**: Audit log shows real-world decision patterns
- **Auto-freeze evidence**: Freeze events demonstrate active threat response

---

## Security Status

Query the current security status at any time:

```typescript
const status = wardex.getStatus();

console.log(status);
// {
//   mode: 'adaptive',
//   frozen: false,
//   evaluationCount: 1247,
//   blockCount: 23,
//   advisoryCount: 89,
//   dailyVolumeWei: '15000000000000000000',
//   signerHealthy: true,
//   intelligenceLastUpdated: '2025-01-15T10:30:00.000Z',
// }
```

---

## What's Next?

- **[Security Tiers](./security-tiers.md)** — Adaptive tier reference
- **[Threat Model](./threat-model.md)** — What Wardex defends against
- **[Core Concepts](../core-concepts.md)** — Full architecture overview
