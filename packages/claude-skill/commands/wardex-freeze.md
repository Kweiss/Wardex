---
name: wardex-freeze
description: Emergency freeze all wallet operations
---

When invoked with `/wardex-freeze`:

1. Explain to the user that this will halt ALL wallet operations until manually unfrozen
2. Ask for confirmation: "Are you sure you want to freeze all wallet operations?"
3. If confirmed, note that the freeze must be triggered through the operator interface or by restarting with the freeze flag

To unfreeze:
- The operator must explicitly call `wardex.unfreeze()` through the SDK
- Or restart the Wardex service without the freeze flag

Display the current status using `wardex_get_status` to show whether the system is currently frozen.
