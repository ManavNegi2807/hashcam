# security/prompt_guard — prompt-injection guard

**Status:** `TESTED` and `MEASURED` on a small hand-written corpus only (`docs/PROMPT_GUARD_EVAL.md`).
**Built in:** Step 10. **Requirements:** R-PIG-01..10.

Deterministic rules; the classifier is off by default and none exists (D-17). The verdict is a
signal to policy, never an authorization. It is **not** a complete injection defence: other
languages, paraphrase and obfuscation are missed, and text *about* injection is flagged. No
Prompt Chainmail code or model is used.
