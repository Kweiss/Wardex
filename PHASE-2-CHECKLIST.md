# Phase 2 Checklist (Weeks 5-8)

## Objective
Ship intelligence, context integrity, output filtering, and risk/policy hardening to production-ready quality.

## Status Legend
- [x] Complete
- [~] In progress
- [ ] Pending

## Workstreams

### 1) Intelligence
- [x] Address and contract analysis pipeline implemented
- [x] Proxy and honeypot bytecode pattern detection implemented
- [x] Address ageDays population from explorer tx history implemented (`@wardexai/intelligence`)
- [x] Add additional timeout/fallback tests for explorer and RPC degradation
- [x] Add fixture coverage for high-risk bytecode variants and false-positive guards

### 2) Context Analyzer
- [x] Rule-based prompt injection detection implemented
- [x] Coherence and trust-source checks implemented
- [x] Tune escalation heuristics with deterministic threshold tests
- [x] Add calibration notes for source trust scoring in docs

### 3) Output Filter
- [x] Private key / mnemonic / keystore filtering implemented
- [x] Default BIP-39 wordlist loading enabled
- [x] Add adversarial corpus tests (obfuscated separators, mixed encodings, multiline variants)

### 4) Risk + Policy
- [x] Composite risk aggregation and tiered policy engine implemented
- [x] Tier override guardrails implemented
- [x] Add tier calibration matrix tests for boundary values and trigger precedence

## Exit Criteria
- [~] All scenario + unit tests for Phase 2 surfaces pass in CI
- [x] No open High/Critical findings on Phase 2 components
- [x] Documentation updated for final Phase 2 behavior and operator defaults

### Exit Criteria Evidence (2026-02-13)
- Local verification: `npm run build` and `npm run test` pass across workspaces (latest run: 194 tests passing, E2E testnet scenarios skipped when local anvil/RPC is unavailable).
- CI coverage exists in `.github/workflows/ci.yml` for TypeScript tests, Solidity tests, and E2E integration tests.
- Security remediation status (`SECURITY-REMEDIATION.md`) reports v1/Phase-2-tracked audit remediations complete for this cycle, with no open High/Critical findings recorded in-repo.
- Documentation for final Phase 2 behavior and conservative operator defaults is now present in:
  - `docs/core-concepts.md` (trust calibration and escalation defaults)
  - `docs/guides/mcp-server.md` and `docs/guides/claude-skill.md` (default mode and env behavior)
  - `defaults/` bundle (`defaults/README.md`, `defaults/wardex.env.default`, `defaults/claude-settings.default.json`)

### Remaining Action to Close Phase 2
- Run CI on the current branch and confirm green status for all relevant jobs, then flip the CI exit criterion to `[x]`.

## Kickoff Completed (Today)
- Implemented address age derivation in intelligence provider using explorer tx history.
- Added unit tests for age population and explorer fallback behavior.
- Added risk-tier calibration tests for boundary and trigger-precedence behavior.
- Added degradation-path tests for intelligence (RPC outage and explorer verification failure handling).
- Added adversarial output-filter tests for mixed-case, punctuation-separated, and multiline mnemonic phrases.
- Added deterministic escalation-threshold tests (5x threshold and 30-minute window) and fixed value fallback for escalation detection.
- Added extra contract-analysis fixtures for false-positive guards and hardened minimal-proxy detection.
- Added source-trust calibration notes to the core concepts docs.
