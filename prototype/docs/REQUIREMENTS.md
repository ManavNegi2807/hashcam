# Agent Black Box: Requirements

Priority: **M** = must have (core demo), **S** = should have, **C** = could have (stretch).
Every requirement has an ID and a way to check it (acceptance criteria).

---

## 1. Purpose and scope

Agent Black Box runs AI web agents through TinyFish, records every step in a tamper-evident, signed log, enforces safety rules (guard), and keeps the final payment under human control.

**In scope:** task runner, recorder and ledger, verifier, guard, payment preparation with human signing on a testnet, UI, Docker packaging, public anchor.
**Out of scope:** real money, real card data, KMS or HSM, multi-signature, independent witness servers, mobile app.

## 2. Users

| User | Goal |
|---|---|
| **End user** | Give a task, see what the agent did, approve payments |
| **Auditor or judge** | Verify a log without trusting the system owner |
| **Developer** | Debug a failed run by replaying steps |

## 3. Functional requirements

### 3.1 Task running

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-01 | User can submit a text task | M | Task box accepts text and starts a run |
| FR-02 | Agent does web work only through TinyFish | M | Every web call appears as a logged step |
| FR-03 | All web calls go through one wrapper (`run_step`) | M | No code path calls TinyFish directly; a test fails if one exists |
| FR-04 | User can stop a running task | S | Stop button ends the run and logs `STOPPED` |
| FR-05 | Run ends with a final answer plus the verified log | M | Result page shows answer and verification badge |

### 3.2 Recording and ledger

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-10 | Each step records time, URL, action, masked result | M | Entry contains all four fields |
| FR-11 | Each step stores a screenshot hash (or page-text hash if no screenshot) | M | Screenshot file name equals its SHA-256 |
| FR-12 | Entries form a SHA-256 hash chain | M | Entry `prev` equals previous entry `hash` |
| FR-13 | Each entry is signed with Ed25519 | M | Signature verifies with the public key |
| FR-14 | Serialization is canonical (sorted keys, fixed separators) | M | Same data always gives the same hash |
| FR-15 | Log is append-only and each write is atomic | M | Killing the process mid-write never leaves a half entry |
| FR-16 | Secrets are masked before hashing | M | A test string with a card number never appears in the log |

### 3.3 Verification

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-20 | Verifier recomputes chain, signatures and screenshot hashes | M | Intact log returns OK |
| FR-21 | Verifier reports the first broken step | M | Edited entry 2 gives "TAMPERED at step 2" |
| FR-22 | Verifier runs from CLI and UI | M | `verify` command and Verify button both work |
| FR-23 | Verifier needs only the log and the public key | M | Works on another machine with no database access |
| FR-24 | Export a run "receipt" file that verifies offline | S | Receipt verifies on a clean machine |

### 3.4 Tamper demo

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-30 | Button to edit one entry | M | Verifier turns red at that step |
| FR-31 | Button to delete a middle entry | M | Verifier turns red at the next step |
| FR-32 | Button to truncate the last entries | M | Verifier compares with the anchor and reports mismatch |

### 3.5 Guard

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-40 | Only allowlisted sites may be used for sensitive actions | M | Off-list site gives `BLOCKED` and a log entry |
| FR-41 | Spending limit per task | M | Amount above the limit gives `BLOCKED` |
| FR-42 | Sensitive actions need human approval | M | No payment step runs without an approval record |
| FR-43 | Blocked and denied attempts are logged | M | Log contains `BLOCKED` or `DENIED` entries |
| FR-44 | Passwords, OTPs and card numbers are never sent to the model or log in full | M | Masked as `****1234` |
| FR-45 | Webpage text is treated as data, not instructions | S | Injection demo page does not change the agent's goal |

### 3.6 Payment (testnet)

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-50 | Agent can only prepare a payment (recipient, amount, site) | M | Agent code has no wallet key or send function |
| FR-51 | Confirmation screen is drawn by a service separate from the agent | M | Agent process cannot change the displayed values |
| FR-52 | Screen shows recipient, amount and site clearly | M | All three visible before the sign button |
| FR-53 | User signs with their own testnet wallet | M | Transaction is created only after user signs |
| FR-54 | Transaction ID and approval are added to the log | M | Payment entry has `approved_by` and `tx_id` |

### 3.7 Anchor

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-60 | Publish the latest hash to a public place (GitHub gist) | M | Gist contains the chain tip and entry count |
| FR-61 | Anchor again every N steps and at run end | S | Multiple anchor records exist for a long run |
| FR-62 | Optional testnet transaction anchor | C | Transaction contains the hash |
| FR-63 | Verifier compares log tip with latest anchor | M | Truncated log is flagged |

### 3.8 UI

| ID | Requirement | Pri | Acceptance criteria |
|---|---|---|---|
| FR-70 | Live timeline with screenshot, hash badge and status per step | M | Updates while the run is in progress |
| FR-71 | Clear green or red verification banner | M | Visible without scrolling |
| FR-72 | Payment confirmation screen | M | See FR-52 |
| FR-73 | Show blocked actions distinctly | S | Blocked rows are highlighted |

## 4. Security requirements

| ID | Requirement | Pri |
|---|---|---|
| SR-01 | Signing key is never in source code or the agent container (env var or secrets manager) | M |
| SR-02 | Agent container has no direct internet access; only `run_step` reaches the web | M |
| SR-03 | Ledger service is the only holder of the signing key | M |
| SR-04 | Payment confirmation service runs separately from the agent | M |
| SR-05 | Logs and screenshots are encrypted at rest | C |
| SR-06 | Access to logs is restricted to authorized users | C |
| SR-07 | Dependencies are pinned and scanned | C |
| SR-08 | A second check confirms a sensitive action matches the user's goal | C |

## 5. Non-functional requirements

| ID | Area | Requirement | Pri |
|---|---|---|---|
| NFR-01 | Tamper-evidence | Any edit, delete or reorder is detected | M |
| NFR-02 | Performance | Recording adds less than 50 ms per step (excluding screenshot capture) | S |
| NFR-03 | Reliability | A crash never corrupts the existing log | M |
| NFR-04 | Portability | `docker compose up` starts the whole system | M |
| NFR-05 | Testability | Tamper tests (edit, delete, truncate) run automatically in pytest | M |
| NFR-06 | Usability | A judge can understand the demo screen in under 10 seconds | S |
| NFR-07 | Observability | Errors are logged with a step number and reason | S |

## 6. Assumptions and constraints

- Testnet only. No real money or real card data.
- A TinyFish API key is available.
- About 48 hours of build time, so core (M) items come first.
- It is not yet confirmed what a TinyFish run returns per step (screenshots, URLs). Check in the first hour. Fallback: capture screenshots from a browser session, or log page text and URL.
- Website content may be false. The log proves what the agent saw, not that it was true.

## 7. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| TinyFish returns no per-step screenshots | Weaker evidence | Fallback capture, or hash page text |
| Prompt injection on a webpage | Wrong agent actions | Guard, approval, limit, content isolation |
| Key leak | Log can be forged | Key outside agent, public anchor |
| Time overrun | Core demo not ready | Build all M items first, skip C items |
| Testnet or gist outage during demo | Anchor demo fails | Pre-record a backup, keep an offline anchor file |

## 8. Definition of done (hackathon)

1. A full demo task runs end to end with a live log.
2. Verifier shows green on an untouched log.
3. Edit, delete and truncate tampering are each caught live.
4. A blocked action and an approved testnet payment both appear in the log.
5. `docker compose up` works on a clean machine.
6. README, architecture and these requirements are in the repo.
