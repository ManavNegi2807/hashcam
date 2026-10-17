# Agent Black Box: Product Requirements Document (PRD)

**Product name:** Agent Black Box (working name; final name not chosen)
**Version:** Draft 0.1
**Related:** `Agent_Black_Box_Final_Architecture_v10.md`, `DESIGN.md`, `PROTOCOL.md`, `REQUIREMENTS.md`
**Status of claims:** everything below is a plan. Nothing here is built or tested for v10. Market statements are assumptions to check with real users, not measured facts.

---

## 1. Summary

AI agents now browse websites, fill forms and call APIs for people and companies. When something goes wrong, or when an auditor asks "what did the agent actually do, and who allowed it?", the usual answer is a log file that anyone with database access could have edited.

Agent Black Box is a **flight recorder for web agents**. It records each run as a signed, tamper-evident history, checks every action against rules before it happens, requires a signed human approval for risky actions, and produces a **receipt** that a third party can verify offline without trusting us.

It is an evidence and auditing product. It does not prove an agent is honest, and it does not prove a real-world action happened unless the observation itself is trustworthy.

## 2. Problem

| Who feels it | Problem today |
|---|---|
| Compliance and audit teams | Agent activity is recorded in ordinary logs. They cannot show an auditor that the logs were not changed afterwards |
| Security teams | Agents read untrusted web pages that can contain hidden instructions. There is no clear record of what the agent saw and what it was allowed to do |
| Finance and operations heads | They want agents to do real work (vendor portals, filings, payments) but cannot prove approvals happened before actions |
| Agent builders | When an agent misbehaves, they cannot replay or prove what happened, and customers do not trust "the agent said it succeeded" |

Root cause: agent output is self-reported, logs are mutable, and approvals are not tied to the exact action.

## 3. Goals and non-goals

### Goals
1. Every run produces a receipt whose integrity anyone can check offline.
2. Editing, deleting or reordering recorded history is detected and the verifier points to where.
3. Risky actions are checked by deterministic rules before they run, and need a signed human approval where policy says so.
4. The receipt is honest about coverage: what was gated, what was only observed, what is unknown.
5. Core works with no paid service and no internet (`LOCAL_ONLY`).

### Non-goals
- Proving an agent is honest, safe or correct.
- Proving a real-world action happened without trustworthy observation.
- Replacing the agent, or being an agent framework.
- Mainnet or real-money payments (testnet only, optional).
- Multi-tenant SaaS, regulator certification, or "AI decides what is allowed". ML output is advisory only.

## 4. Users and personas

| Persona | Needs | How they use the product |
|---|---|---|
| **Compliance or audit lead** (primary buyer) | Evidence an auditor will accept | Reads receipts, runs the verifier, sets policy |
| **Security engineer (CISO team)** | Control and visibility over what agents may do | Writes policies and mandates, reviews findings |
| **Agent developer** | Prove what the agent did, debug failures | Connects an agent through an adapter, uses replay and drift diffs |
| **Approver** (finance or ops manager) | Approve or deny risky actions quickly and safely | Gets an approval request, signs on their own device |
| **External auditor or customer** | Check a receipt without trusting the vendor | Runs the offline CLI verifier |

## 5. Use cases

Strongest fit (to validate with interviews): banking and fintech back-office, insurance claims, accounting and CA firms, vendor payments and procurement, IT operations.
Good fit: government and tender portals, real estate, education admissions, e-commerce seller portals, supply chain, travel.

Example flows:
1. **Vendor portal update.** Agent updates bank details on a vendor portal. Policy requires approval. Manager signs. Receipt proves the approval came before the action.
2. **Filing submission.** Agent submits a tax or compliance form on an allowed site within a signed mandate. Auditor verifies the receipt months later.
3. **Prompt-injection attempt.** A page contains hidden instructions. The guard flags it, policy blocks the follow-up action, and the receipt shows both.
4. **Incident review.** Something went wrong. The team replays the run, diffs it against a rerun, and shows the history was not edited.

## 6. Product principles

1. **Do not ask to be trusted.** Anyone can verify a receipt with a small offline tool.
2. **Say what we did not see.** Missing evidence is `UNKNOWN`, never a pass.
3. **Rules decide, ML advises.** Deterministic policy authorizes. ML and prompt scores only raise flags.
4. **Local first.** Core runs on one machine, no vendor lock-in.
5. **Honest claims.** Every public claim is `SPECIFIED`, `IMPLEMENTED`, `TESTED`, `MEASURED` or `UNVERIFIED`.

## 7. Feature requirements

Priority: **P0** must exist for the hackathon demo, **P1** next, **P2** later. Detailed testable requirements are in `REQUIREMENTS.md` (area codes in the last column).

| # | Feature | What the user gets | Priority | Area |
|---|---|---|---|---|
| F1 | **Signed run history** | Every run recorded as canonical events in a Merkle tree with signed checkpoints | P0 | PRO, CRY, SIG |
| F2 | **Receipt export and offline verifier** | A single file plus a CLI that checks it, with a clear pass or fail and the broken point | P0 | REC |
| F3 | **Tamper demo** | Edit an event or artifact, or delete a run, and watch the verifier catch it | P0 | GLB, HKC |
| F4 | **Replay adapter** | Deterministic, zero-cost runs labeled `REPLAY` for testing and demos | P0 | ADP |
| F5 | **Policy gateway** | Allow, deny or require approval before an action, with versioned rules | P0 | POL, COV |
| F6 | **Coverage labels** | Each receipt states `TASK_LEVEL`, `STEP_OBSERVED` or `STEP_GATED` honestly | P0 | COV |
| F7 | **Artifact provenance** | Screenshots, HTML and downloads hashed and hash-linked, bound into the checkpoint | P0 | ART |
| F8 | **Separate signer** | Isolated key holder that recomputes roots and refuses forks or rollback | P0 | SIG |
| F9 | **Local Playwright adapter** | Real browser runs that truly pass through the gateway | P1 | ADP |
| F10 | **Global log, witness, Git anchor** | Detects deleted runs; second-device witness and public anchor | P1 | GLB, WIT |
| F11 | **Signed approvals** | Approver signs the exact action on their own device | P1 | APR |
| F12 | **Signed mandate** | A signed statement of what the agent may do; verifier checks compliance | P1 | APR |
| F13 | **Field commitments** | Sensitive values hidden but provable; deletion without breaking proofs | P1 | CMT |
| F14 | **Semantic invariant checks** | Rules such as "success needs an observed postcondition", with evidence events | P1 | SEM |
| F15 | **Prompt-injection guard** | Deterministic checks on untrusted page text, as a signal to policy | P1 | PIG |
| F16 | **Dashboard** | Run list, live timeline, five separate assessment channels, receipt viewer | P1 | UI |
| F17 | **TinyFish adapter** | Optional remote execution, capped at `STEP_OBSERVED`, with budget guards | P2 | TFY |
| F18 | **Replay drift** | Rerun a task and diff the traces | P2 | ANO |
| F19 | **Behavior anomaly auditor** | Advisory trajectory score; rules baseline first, model later | P2 | ANO |
| F20 | **WASM verifier, Temporal, Litestar, IPFS** | Browser verification and heavier infrastructure | P2 | HKC |
| F21 | **Human-approved testnet payment** | Optional payment flow using signed approvals | P2 (optional) | EXT |

## 8. User stories and acceptance

Each story is done only when its test passes. Until then it is `SPECIFIED`.

| ID | Story | Acceptance |
|---|---|---|
| US-1 | As an auditor, I can verify a receipt offline without contacting the vendor | CLI returns per-dimension results and an overall `VALID` for an untouched receipt |
| US-2 | As an auditor, I see exactly where history was changed | Editing one event makes the verifier name that event and mark `evidence_integrity` `FAIL` |
| US-3 | As a security lead, I can see a deleted run was deleted | `abb verify-global` reports the missing run against the anchored global checkpoint |
| US-4 | As a security lead, risky actions are blocked or need approval before they happen | For `STEP_GATED` runs every dispatch has an earlier authorization, and a violation fails `observation_coverage` |
| US-5 | As an approver, I approve the exact action I was shown | The signed summary digest matches the request; expired or mismatched approvals fail |
| US-6 | As a compliance lead, I can delete a person's data without breaking old receipts | Shredding a salt keeps all proofs valid; dependent checks show `UNKNOWN` |
| US-7 | As a developer, I can see what the receipt does not cover | Receipt shows declared coverage, in-scope actions and `UNKNOWN` areas |
| US-8 | As a buyer, I can run it without any paid service | `LOCAL_ONLY` demo works offline after images are downloaded |

## 9. Hackathon scope (MVP)

The goal is a demo that proves the core idea, not the full architecture.

**In:** F1 to F8, plus F10 (global log with Git anchor and one extra witness) if time allows. One FastAPI service, plain PostgreSQL, MinIO, Rust CLI, separate signer, replay scenarios.

**Demo script (about 5 minutes):**
1. Run a replay scenario that fills a form and needs approval.
2. Export the receipt and verify it: `VALID`, with coverage shown honestly.
3. Edit one event in the database. Verify again: `INVALID`, with the exact event named.
4. Swap an artifact file. Verify: artifact integrity fails.
5. Delete a whole run. `abb verify-global` flags the gap.
6. Show a `STEP_OBSERVED` TinyFish-style run labeled as such (only if the spike is done).

**Out for now:** Temporal, Litestar split, TimescaleDB, IPFS, WASM, ML model, multi-tenancy.

## 10. Success metrics

Targets are proposals. Measure them; do not claim them before measurement.

| Area | Metric | Target |
|---|---|---|
| Correctness | Tamper cases caught by the verifier (edit, reorder, delete, artifact swap, fork) | 100% of the test suite |
| Interoperability | Rust CLI and the Python side agree on all test vectors | 100% |
| Usability | Time for a new person to verify a receipt | Under 5 minutes |
| Demo | Fresh checkout to working demo | One command, under 10 minutes |
| Pilot (later) | Pilots where an auditor accepted a receipt as evidence | At least 1 of the first 3 |
| Pilot (later) | Policy blocks that were true positives, per review | Measured, no target set |

## 11. Business model and go-to-market (assumptions, not validated)

- **Buyers:** compliance or audit heads, CISOs, finance heads.
- **Path:** free pilot on one small process (2 to 4 weeks), self-hosted first.
- **Open source:** the verifier and protocol should be open so trust does not depend on us.
- **Paid later:** per agent or by support contract. **Prices are not set.**
- **Trust position:** "do not trust us, verify the receipt."
- **Honest limits to state up front:** unobserved actions, a compromised capture host, the truth of timestamps, and collusion of all witnesses are not covered.

## 12. Competitive position (to research)

Not yet researched. To do before any claim: list existing agent observability tools (tracing and logging products) and audit-log or transparency-log products, and write what each does and does not give (tamper evidence, offline verification, pre-action gating, signed approvals). Until then, do not state that this is unique or that nothing like it exists.

## 13. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Scope is too large for the hackathon | Nothing finished | Hackathon cut (P0 only); everything else behind interfaces |
| Claims exceed evidence | Loss of trust | Claims ledger; verifier shows `UNKNOWN` honestly |
| Gate coverage is weaker than advertised | Wrong sense of safety | `STEP_GATED` only with bypass tests; remote adapters capped at `STEP_OBSERVED` |
| Compromised capture host fabricates evidence | Receipts valid but false | State it plainly; use witnesses, trustworthy observation, mandate checks |
| Sensitive data in the log | Privacy and legal exposure | Field commitments and crypto-shredding; log redaction |
| TinyFish credits run out or API differs | Demo blocked | Optional adapter; replay is the default; hard budget cap ($15 plan) |
| Prompt-guard classifier license (BSL 1.1) | Cannot ship | Deterministic checks by default; classifier off until reviewed |
| False positives from rules or ML | Users ignore warnings | Report precision and recall; ML advisory only |
| Key loss or theft | Cannot sign, or forged history | Offline key backup, rotation procedure, fail-closed signer |
| Same-machine "witnesses" look independent | False assurance | `failure_domain` and `NOT_INDEPENDENT` result |

## 14. Dependencies and assumptions

- TinyFish API access and credits (optional, $15 plan: 6 agent tests, 3 search/fetch tests, 3 validation reruns, 3 reserve).
- Docker Compose host with enough disk for PostgreSQL and MinIO.
- A second device for the independent witness, and a public Git repository for the anchor.
- A person who holds an approver key (CLI first).
- Assumption: buyers value verifiable evidence enough to adopt a new tool. This is untested; interview at least five potential users before building beyond the MVP.

## 15. Open questions

1. Product name (candidates discussed, none chosen; availability unchecked).
2. Is the optional payment flow part of the hackathon demo or left out?
3. Is the signed-approval design (approver holds a key, CLI first) acceptable?
4. Which first vertical for the pilot story: finance back-office, compliance filings or IT operations?
5. Which license for the verifier and protocol?
6. Real TinyFish capability: per-step records, retention, gating, metering (needs the spike).

## 16. Release milestones

| Milestone | Content | Done when |
|---|---|---|
| M0 | Protocol frozen for first slice with test vectors | Vectors pass in Rust and Python |
| M1 | Rust core, CLI, signer, plain Postgres, replay | Receipt verifies; tamper cases caught |
| M2 | Demo script end to end, including deleted-run detection | Demo runs from a fresh checkout |
| M3 | Playwright gating, signed approvals, mandate | Bypass tests pass |
| M4 | Dashboard, semantic and prompt checks, TinyFish spike | Five assessment channels visible |
| M5 | Pilot hardening | Backup and restore tested, license review done |

## 17. Traceability

| PRD feature | Architecture v10 | Protocol | Requirement groups |
|---|---|---|---|
| F1, F2 | 7, 8, 16 | 3 to 10, 15, 16 | PRO, CRY, REC |
| F3 | 8, 22 | 8.5, 16 | GLB, HKC |
| F5, F6 | 6, 14 | 7 | POL, COV |
| F7 | 15A.B | 9 | ART |
| F8 | 9 | 11 | SIG |
| F10 | 8, 10 | 8.5, 12, 13 | GLB, WIT |
| F11, F12 | 7 | 5.6, 5.7 | APR |
| F13 | 7, 11 | 5.5 | CMT |
| F14, F15, F18, F19 | 15, 15A | 14 | SEM, PIG, ANO |
| F16 | 16 | none | UI |
| F17 | 13 | 7 | TFY |
