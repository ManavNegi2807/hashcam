# security/anomaly — behaviour anomaly rules and replay drift

**Status:** `TESTED` for the rules and the drift comparison; **no trained model exists**.
**Built in:** Step 11. **Requirements:** R-ANO-01..05, 09..11 (R-ANO-06..08 need a model and labeled data and are not met).

Readable rules first. Policy outcomes are never an input (R-ANO-05, tested). A score is a rule
sum, not a probability. A failure here changes nothing else. Advisory only, never in the trust path.
