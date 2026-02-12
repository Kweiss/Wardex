# Threat Model

Wardex's security model begins with an unusual premise: **the AI agent itself is part of the threat surface**. Unlike traditional wallet security, where the user is assumed to be trustworthy and the attacker is external, an AI agent can be manipulated into acting against the user's interests without any external system being compromised.

This document describes the threats Wardex defends against, the trust boundaries it enforces, and the limitations of its protections.

---

## Attacker Capabilities

Wardex assumes an attacker who can:

- **Inject prompts** into the agent's context via user messages, tool outputs, web content, or cross-MCP data flows
- **Compromise MCP tools** so that tool responses contain embedded transaction instructions or social engineering payloads
- **Deploy malicious contracts** that pass superficial inspection but contain SELFDESTRUCT, unsafe DELEGATECALL, or honeypot logic
- **Social engineer the agent** through urgency manipulation, authority impersonation, or trust escalation across multi-turn conversations
- **Gradually escalate** transaction values or frequency to desensitize the security system over time
- **Request key material** by tricking the agent into outputting seed phrases, private keys, or keystore data in its responses

Wardex does **not** assume an attacker with:

- Root access to the host machine running the signer process
- The ability to tamper with the WardexShield binary or its dependencies at runtime
- Access to the shared HMAC secret between the SDK and isolated signer

---

## Trust Boundaries

Wardex defines four trust zones, listed from most trusted to least:

```
User Input (highest trust)
    |
    v
AI Assistant (conditional trust - can be manipulated)
    |
    v
MCP Tools / External Data (low trust - attacker-controlled content)
    |
    v
On-chain Data / Contracts (untrusted - adversarial environment)
```

### Boundary 1: User to Assistant

User instructions are the highest-trust input, but even these are evaluated. Prompt injection attacks can be embedded in what appears to be a user message (for example, a user pasting content from a malicious website). The context analyzer scans all messages regardless of role.

### Boundary 2: Assistant to MCP Tools

MCP tool outputs are treated as low-trust data. Any tool response that contains transaction instructions, authorization claims, or key material requests is flagged by cross-MCP source verification. The `InstructionSource` type tracks the origin and trust level of every transaction trigger.

### Boundary 3: SDK to Signer

The isolated signer process is a hard trust boundary. The AI agent process never has access to private key material. Communication happens over a Unix socket, and every signing request requires a time-limited HMAC-SHA256 approval token that proves the Wardex pipeline approved the specific transaction.

### Boundary 4: Off-chain to On-chain

The WardexValidationModule (ERC-4337) provides on-chain enforcement that operates independently of the SDK. Even if the entire off-chain stack is bypassed, on-chain spending limits, evaluator signature verification, and emergency freeze hold.

---

## Defense Layers

Wardex implements seven defense layers. Each layer catches a different class of attack, and they work in concert so that bypassing one does not defeat the system.

### 1. Key Isolation

**What it defends against:** Complete agent compromise leading to key theft.

The private key lives in a separate OS process (the isolated signer), communicating over a Unix socket with restrictive permissions (`0o600`). The agent process can request signatures but never receives the key itself. Even if an attacker gains full control of the AI agent, they cannot extract the private key.

The signer verifies a cryptographic approval token (HMAC-SHA256) before signing. Tokens are bound to a specific transaction hash and expire after 5 minutes, preventing replay attacks. Timing-safe comparison is used to prevent timing side-channel attacks on the HMAC.

**Key files:** `packages/signer/src/isolated-process.ts`

### 2. Context Integrity

**What it defends against:** Prompt injection, jailbreak attempts, social engineering, cross-MCP manipulation.

The context analyzer (pipeline stage 1) scans all conversation messages for 10 known injection patterns, including instruction overrides, role reassignment, fake system messages, jailbreak techniques, encoded instruction smuggling, hidden HTML instructions, urgency manipulation, false authorization claims, key material requests, and broad fund redirection.

Source verification checks the trust level and type of the instruction that triggered the transaction. Coherence checking detects transactions that do not match the recent conversation topic. Escalation detection flags transaction values that increase by 5x or more within a 30-minute window.

**Key files:** `packages/core/src/middleware/context-analyzer.ts`

### 3. Transaction Validation

**What it defends against:** Malicious contracts, honeypots, unverified code, denylisted addresses, infinite token approvals.

Transaction validation spans three pipeline stages: address checking (stage 4), contract checking (stage 5), and policy enforcement (stage 9).

The address checker evaluates targets against operator-defined allowlists and denylists, and optionally queries on-chain reputation (address age, transaction count, risk factors). The contract checker analyzes bytecode for SELFDESTRUCT, DELEGATECALL, CALLCODE opcodes, EIP-1167/EIP-1967 proxy patterns, and unverified source code. The policy engine enforces global transaction limits (max per-tx value, max daily volume, max approval amount, max gas price).

**Key files:** `packages/core/src/middleware/address-checker.ts`, `packages/core/src/middleware/contract-checker.ts`, `packages/core/src/middleware/policy-engine.ts`

### 4. Behavioral Analysis

**What it defends against:** Safety drift, gradual escalation, anomalous activity patterns.

The behavioral comparator (pipeline stage 6) maintains a statistical profile of the agent's normal transaction patterns: value mean and standard deviation, transaction frequency, active hours, and known contracts. Four detectors flag deviations:

- **Value anomaly:** Transaction value significantly above the historical average (configurable sensitivity: 1.5x/2.5x/4x standard deviations)
- **New contract:** First-time interaction with an unknown contract address
- **Frequency anomaly:** Burst of transactions exceeding the baseline rate
- **Timing anomaly:** Transactions outside the agent's normal active hours

**Key files:** `packages/core/src/middleware/behavioral-comparator.ts`

### 5. Output Filtering

**What it defends against:** Data exfiltration via AI responses (seed phrases, private keys, keystore files).

The output filter is a mandatory component that cannot be disabled or bypassed. It scans all AI text responses, tool outputs, and data before any external destination. It detects:

- Hex-encoded private keys (64 hex characters with or without 0x prefix)
- BIP-39 mnemonic sequences (12, 15, 18, 21, or 24 word patterns with uncommon-word heuristics to reduce false positives)
- JSON keystore file patterns

Detected sensitive data is replaced with `[REDACTED BY WARDEX]`. Full keystore file output causes the entire response to be blocked.

**Key files:** `packages/core/src/output-filter.ts`

### 6. Session Key Limits

**What it defends against:** Blast radius of a compromised or bypassed SDK.

ERC-7715 session keys (managed by `SessionManager`) constrain what a session key can do, even if the Wardex evaluation pipeline is bypassed:

- **Contract allowlist:** Only specified target contracts can be called
- **Per-transaction value limit:** Maximum wei value per single transaction
- **Daily volume cap:** Maximum cumulative daily spend
- **Time-bounded expiration:** Session keys expire after a configured duration
- **Infinite approval blocking:** Optional rejection of any ERC-20 `approve` with amount > 2^128 or `setApprovalForAll`

Session keys can be revoked immediately, and rotation creates a fresh key with the same constraints. Private keys are zeroed from memory on revocation or cleanup.

**Key files:** `packages/signer/src/session-manager.ts`

### 7. On-chain Enforcement

**What it defends against:** Complete off-chain compromise (SDK bypass, agent takeover).

The `WardexValidationModule` is a Solidity contract compatible with ERC-4337 (Account Abstraction) smart accounts. It enforces:

- **Evaluator signature verification:** Every UserOperation must include an ECDSA signature from the designated Wardex evaluator address
- **Spending limits:** Per-transaction and per-day limits for ETH and ERC-20 tokens, tracked on-chain with daily reset
- **Emergency freeze:** The account can be frozen on-chain, blocking all transactions regardless of off-chain state

These protections are immutable once deployed and operate independently of the TypeScript SDK.

**Key files:** `packages/contracts/src/WardexValidationModule.sol`

---

## What Wardex Does NOT Defend Against

The following attack scenarios are outside Wardex's protection scope:

### Compromised Signer Process

If an attacker gains access to the signer process itself (the isolated OS process holding the encrypted private key), Wardex cannot prevent key extraction. For high-value deployments, use a TEE (Trusted Execution Environment) or MPC (Multi-Party Computation) signer backend instead of the isolated process signer. Wardex supports TEE and MPC signer configurations via the `TEESignerConfig` and `MPCSignerConfig` types.

### Legitimate User Requests to Risky Addresses

Wardex will advise against sending funds to addresses with poor reputation or known risk factors, but it does not override an informed user's explicit intent. If the user reviews a warning and still confirms the transaction, Wardex allows it (unless global policy limits are exceeded). The user always has final authority.

### Zero-day Smart Contract Exploits

Contract bytecode analysis detects known dangerous patterns (SELFDESTRUCT, unsafe DELEGATECALL, proxy patterns, unverified code), but it cannot detect novel vulnerabilities in otherwise-clean contract logic. A contract that passes bytecode analysis may still contain reentrancy bugs, oracle manipulation, or other logic-level exploits that require source-code auditing to identify.

### Side-channel Attacks on the Host System

Wardex does not protect against attacks on the operating system, hardware, or network infrastructure where the agent runs. Memory dumps, process injection, or network interception at the OS level are outside the SDK's threat model. Standard host security practices (encrypted disks, network segmentation, secure boot) remain the operator's responsibility.

### On-chain Front-running and MEV

Wardex evaluates transactions before submission but does not protect against on-chain front-running, sandwich attacks, or MEV extraction after the transaction enters the mempool. Operators should use private transaction submission (e.g., Flashbots Protect) for high-value DeFi operations.

---

## Risk Score Weighting

The risk aggregator combines scores from three analysis dimensions using weighted averaging:

| Dimension | Weight | Rationale |
|---|---|---|
| Context (prompt injection) | 40% | Compromised decision-making is the most dangerous scenario for an AI agent |
| Transaction (on-chain signals) | 35% | Direct financial threat from malicious contracts and addresses |
| Behavioral (anomaly detection) | 25% | Deviation from baseline is an indirect signal that reinforces other findings |

If any single dimension score reaches 90 or above, the composite score is raised to at least 80, ensuring that a critical finding in any dimension triggers high-tier enforcement.

---

## Further Reading

- [Attack Vectors](./attack-vectors.md) -- Detailed catalog of the 7 attack categories Wardex tests against
- [Security Tiers Reference](./security-tiers.md) -- How adaptive tiers map risk scores to enforcement actions
- [Core Concepts](../core-concepts.md) -- Architecture overview of the middleware pipeline
- [Glossary](../glossary.md) -- Definitions of all security terms used in these docs
