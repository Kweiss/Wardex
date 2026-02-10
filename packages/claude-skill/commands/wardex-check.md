---
name: wardex-check
description: Check if an Ethereum address is safe to interact with
---

When invoked with `/wardex-check`, ask the user for:
- The Ethereum address to check (0x-prefixed)
- Chain ID (optional, default: 1 for Ethereum mainnet)

Then call `wardex_check_address` with those parameters and present the results:
- Whether the address is considered safe (risk score < 30)
- The transaction risk score (0-100)
- Any findings about the address (denylist status, reputation issues, etc.)
- A clear recommendation: safe to interact, proceed with caution, or avoid

If the address is on a denylist, emphasize this clearly and advise against interaction.
