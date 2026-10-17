# security/semantic — semantic invariant monitor

**Status:** `TESTED`. **Built in:** Step 10. **Requirements:** R-SEM-01..04, 06, 07 (R-SEM-05, mining, is deferred).

Four hand-written invariants with known-good, known-bad and unobserved traces. A step that was
never observed is `UNKNOWN`, never a pass. A finding can only lead to an escalation a policy
named; this package imports nothing that could authorize.
