---
name: wardex-evaluate
description: Evaluate a transaction for security threats
---

When invoked with `/wardex-evaluate`, ask the user for transaction details:
- Target address (to)
- Value in ETH (will be converted to wei)
- Calldata (optional, for contract interactions)
- Chain ID (default: 1 for Ethereum mainnet)

Then call `wardex_evaluate_transaction` with those parameters and present the
security verdict clearly, including:
- Decision (SAFE / WARNING / BLOCKED / FROZEN)
- Risk scores (context, transaction, behavioral, composite)
- All security reasons found
- Suggestions for improving safety if the transaction was blocked
