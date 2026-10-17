# Agent Black Box: Requirements

**Based on:** `Agent_Black_Box_Final_Architecture_v9_ML_Integrated.md` (v9)
**Related:** `DESIGN.md`, `PROTOCOL.md`
**Status:** DRAFT 0.2 (adds the architecture-review decisions D-10 to D-19)
**Claim status of every requirement below:** `SPECIFIED`. None is `IMPLEMENTED`, `TESTED` or `MEASURED` for v9 yet. v9 itself says implementation and security claims stay unverified until tests pass.

## 1. How to read this document

- **Priority** uses the RFC 2119 words. MUST and MUST NOT are release gates. SHOULD is expected unless a reason is written down. MAY is optional.
- **v9** is the section of the architecture the requirement comes from. `ext` (extension) means it is not in v9; the D-number is the decision in `PROTOCOL.md` section 20 or `DESIGN.md` section 24.
- **Prototype** says what the existing Python prototype already has: `Done` (exists), `Partial` (something similar exists), `None` (nothing yet). It is a status of the prototype, not a claim that the v9 requirement is met. The 21 pytest tests cover only the hash chain, canonical JSON, verifier, masking and guard of the prototype.
- Requirement text is a restatement of v9 in testable form. Where v9 left a choice open, the choice is in `PROTOCOL.md` section 20 or `DESIGN.md` section 24 as a decision (`D-nn`).

## 2. Summary

- Requirements in total: **199**
- Prototype status: **2** Done, **55** Partial, **142** None.
- **v10 build status (2026-10-17, Steps 0, 7, 10, 11):** `TESTED`: `R-ADP-01` and `R-TST-04` (Playwright, local probe site), `R-COV-03`, `R-COV-07`, `R-SEM-01`..`04`, `06`, `07`, `R-PIG-01`..`07`, `09`, `R-UI-02`, `04`, `05`, `R-ANO-01`..`05`, `09`..`11`, `R-ADP-04` (replay), `R-TFY-01`, `03`..`07` **against a mock and a local fake of the published API**; `R-TFY-08` `MEASURED` on two connector runs (`docs/TINYFISH_SPIKE.md`). `MEASURED`: `R-PIG-09` on a 57-item hand-written corpus only. Not met: `R-UI-01` (plain HTML, not Next.js), `R-UI-03` (no SSE view), `R-SEM-05` (deferred), `R-ANO-06`..`08` (no model, no labeled data), `R-TFY-02` (the client has not yet run live with the user's key), `R-COV-04`/`06` hold by capping, not by evidence. `R-PIG-08` holds: no third-party code or model is used.
- **v10 build status (2026-10-16, Step 9):** `TESTED`: `R-APR-01`..`R-APR-08`, `R-CMT-01`..`R-CMT-04`, `R-CMT-06`, `R-CMT-07` (the last as documentation here and in `PROTOCOL.md`). `R-CMT-05` is `IMPLEMENTED` with a stated interpretation (question Q17). The approver client is a CLI (question Q8); WebCrypto and WebAuthn are not built.
- **v10 build status (2026-10-16, Steps 6 and 8):** `TESTED`: `R-ART-01`..`R-ART-07`, `R-DAT-09`, `R-DAT-11`, `R-DAT-12` (cleanup of abandoned temp objects), `R-WIT-01` (rule), `R-WIT-02`, `R-WIT-03`, `R-WIT-04`, `R-WIT-06`, `R-WIT-09`, `R-WIT-10`, `R-GLB-05` (with `--anchor`), `R-GLB-06` (the rollback beat states the limit), `R-HKC-07`. `IMPLEMENTED` but **not** satisfied as written: `R-DAT-08` and `R-DAT-10` (artifacts are in a local content-addressed directory, not MinIO), `R-WIT-01` and `R-WIT-05` (the quorum and a public Git anchor need a second device and a repository that were not available). Still `None`: `R-TST-02` crash windows around upload, `R-DAT-13` (IPFS, deferred).
- **v10 build status (2026-10-16, Step 5):** the demo runs end to end. Added as `TESTED`: `R-ADP-02`, `R-ADP-03`, `R-COV-01`, `R-COV-02`, `R-COV-05`, `R-COV-07`, `R-POL-01`, `R-POL-02` (the implemented rules), `R-POL-03`, `R-POL-04`, `R-POL-06`, `R-REC-01`, `R-REC-02`, `R-REC-03`, `R-REC-04`, `R-REC-05`, `R-REC-06` (wording), `R-GLB-01`, `R-GLB-03`, `R-GLB-04`, `R-HKC-07` (apart from the artifact beat), `R-PRO-08`, and tamper cases TS-01 to TS-06, TS-12, TS-15, TS-16. `IMPLEMENTED` only: `R-ADP-04` (replay determinism is used but not yet asserted by a test). Still `None`: `R-REC-07` WASM, `R-REC-10` published verifier build, `R-REC-11` receipt vectors (the tamper suite covers the cases; the frozen vector files are not written).
- **v10 build status (2026-10-16):** Steps 0b, 1, 2, 3 and 4 of `IMPLEMENTATION_PLAN.md` are done. Step 4 adds, `TESTED` (Rust unit and integration tests plus HTTP contract and fault tests against the running binary): `R-SIG-01`, `R-SIG-02`, `R-SIG-03`, `R-SIG-04`, `R-SIG-05`, `R-SIG-06` (documented), `R-SIG-07`, `R-SIG-08`, `R-SIG-09`, `R-SIG-10`, `R-SIG-11`, `R-SIG-12`, `R-GLB-02`. `IMPLEMENTED` but not tested: `R-OPS-03` at the file level only (the compose isolation rules are checked by `tools/check_key_volume_isolation.py`, but the stack has never been started). Still `None`: `R-CRY-05` key rotation (the record type exists and verifies, the signer never emits one), `R-SIG-13` offline key generation and tested restore.
- **v10 build status (2026-10-15):** Steps 0b, 1, 2 and 3 of `IMPLEMENTATION_PLAN.md` are done. Step 3 adds, `TESTED` against a real PostgreSQL 18.4: `R-DAT-02`, `R-DAT-03`, `R-DAT-04`, `R-DAT-05`, `R-PRO-04`, `R-PRO-05`, `R-PRO-08` (envelope level), `R-RUN-01`, `R-RUN-03`, `R-SVC-02`, `R-SVC-03`, `R-SVC-05`, `R-HKC-01`, `R-HKC-03`. `IMPLEMENTED` but not tested: `R-OPS-01`, `R-OPS-02`, `R-OPS-03`, `R-OPS-04`, `R-OPS-05` (the Compose stack was never started). Still `None`: `R-DAT-06` roles and grants, `R-DAT-07` to `R-DAT-13`, `R-SVC-04` (no benchmark).
- **Previously (Step 2):** `TESTED` in Rust and cross-checked in Python: `R-PRO-02`, `R-PRO-03`, `R-PRO-06`, `R-CRY-01`, `R-CRY-02`, `R-CRY-03`, `R-TST-01` (for the frozen vector sets), `R-REC-02`, `R-REC-03`, `R-REC-04`, `R-REC-05` (the dimension and precedence model only, not a receipt), `R-CRY-05` (rotation records only), `R-OPS-05` (build-context hygiene). Partly covered: `R-GLB-05` (`abb verify-global` reads a file of run roots, not the database), `R-CRY-06` (one Rust core serves the CLI; the signer and WASM do not exist yet). Everything else is unchanged.
- Biggest gaps: Rust core, Merkle tree and checkpoints, separate signer, witnesses, PostgreSQL and MinIO, Temporal, Litestar ingestion, adapters and coverage labels, the four ML and security modules, receipts, WASM verifier, and the Next.js UI.

## 3. Requirements by area
### SYS: System profiles and truthful claims

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-SYS-01 | The system MUST support two profiles: `LOCAL_ONLY` (default) and `CONNECTED_EVIDENCE` (opt-in). | §1 | MUST | None |
| R-SYS-02 | In `LOCAL_ONLY`, execution, event recording, cryptography, storage and verification MUST work with no internet after images and models are downloaded. | §1 | MUST | None |
| R-SYS-03 | TinyFish, public anchors and remote witnesses MUST be disabled by default. External services are adapters and MUST NOT be required for core operation or for receipt verification. | §1 | MUST | Partial |
| R-SYS-04 | The system MUST NOT claim that a cryptographically valid receipt proves an external browser action really happened. It proves the signed history is unaltered relative to trusted checkpoints and records declared source and coverage. | §1 | MUST | Partial |
| R-SYS-05 | The product MUST be described as evidence and behavioral auditing, not as proof that an agent is honest or that a real-world action occurred. | §18 | MUST | Partial |
| R-SYS-06 | The project MUST have no required hosted-service bill. Optional paid services (TinyFish) MUST be guarded against accidental spend. | §2 | MUST | Partial |

### RUN: Run lifecycle

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-RUN-01 | A run MUST be created with a declared task, adapter, policy version and requested coverage level. | §5 | MUST | Partial |
| R-RUN-02 | Runs MUST be orchestrated by a durable workflow engine (self-hosted Temporal) with retries, timers, cancellation and recovery. | §2, §5 | MUST | None |
| R-RUN-03 | A worker MUST hold a lease with a monotonically increasing fencing token. A stale worker MUST NOT commit after a newer worker takes over. | §5 | MUST | None |
| R-RUN-04 | All legal run-state transitions MUST be defined, and invalid transitions MUST be rejected at the service and database boundary. | §5 | MUST | None |
| R-RUN-05 | The system MUST NOT blindly retry an irreversible action after a crash. If an outcome is uncertain it MUST record `OUTCOME_UNKNOWN` and reconcile before retrying. | §5 | MUST | None |
| R-RUN-06 | Retries MUST use idempotency keys and adapter-specific retry rules. | §5 | MUST | None |
| R-RUN-07 | Finalization MUST freeze the run's event prefix, compute a Merkle root, and ask the signer to verify the extension from the previous checkpoint. | §5 | MUST | None |
| R-RUN-08 | The ML auditor's output MUST be advisory and recorded separately. | §5 | MUST | None |

### COV: Coverage levels

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-COV-01 | The system MUST support `TASK_LEVEL`, `STEP_OBSERVED` and `STEP_GATED`, each with the safe claim defined in the protocol. | §6 | MUST | None |
| R-COV-02 | ReplayAdapter output MUST always be labeled `REPLAY` or `SIMULATED`. | §6 | MUST | None |
| R-COV-03 | Local Playwright MAY declare `STEP_GATED` only if all in-scope actions (navigation, clicks, form submits, downloads, relevant network requests) are mediated by the gateway. Otherwise coverage MUST be downgraded. | §6 | MUST | None |
| R-COV-04 | TinyFish coverage MUST follow the evidence actually available. It MUST NOT be inferred from a final answer or a list of reported steps, and MUST NOT be `STEP_GATED` unless every in-scope action is verifiably gated before dispatch. | §6, §13 | MUST | None |
| R-COV-05 | Missing evidence MUST be reported as `UNKNOWN` or `INCOMPLETE`, never as proof that an action did not occur. | §6 | MUST | Partial |
| R-COV-06 | A run with `mode = LIVE_EXTERNAL` MUST be capped at `STEP_OBSERVED` unless `COVERAGE_DECLARED.evidence_ref` points to a recorded capability-test report that shows pre-dispatch gating (D-14). | §6, §13 (D-14) | MUST | None |
| R-COV-07 | For declared `STEP_GATED`, every `ACTION_DISPATCHED` MUST have an earlier `ACTION_AUTHORIZED` with the same action ID. The verifier MUST check this and report `observation_coverage = FAIL` otherwise (D-14). | §6, §15A.A (D-14) | MUST | None |

### PRO: Event protocol and canonical encoding

Details are in `PROTOCOL.md` sections 3 to 5.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-PRO-01 | The protocol MUST be frozen in `docs/PROTOCOL.md`, with cross-language test vectors passing, before production receipts are emitted. | §7 | MUST | None |
| R-PRO-02 | Canonical JSON MUST use RFC 8785 (JCS), with conformance vectors in the repository. | §7 | MUST | Partial |
| R-PRO-03 | Protocol numbers MUST be integers in `[-(2^53-1), 2^53-1]`. Floats, NaN, infinities and ambiguous number forms MUST be rejected. | §7 | MUST | Partial |
| R-PRO-04 | The exact canonical byte sequence MUST be stored. Signed bytes MUST NOT be recovered by re-serializing PostgreSQL `JSONB`. | §7 | MUST | None |
| R-PRO-05 | The protocol MUST define UTF-8 encoding, Unicode handling, required fields, optional-field behavior, maximum payload sizes and schema versioning. | §7 | MUST | Partial |
| R-PRO-06 | Hashing MUST use SHA-256 with explicit, versioned domain tags for event leaves, internal nodes, checkpoint signing payloads, artifacts and protocol identifiers. | §7 | MUST | None |
| R-PRO-07 | Artifact hashing MUST be over the raw artifact bytes. Metadata MUST carry the digest, media type, size and capture provenance. | §7 | MUST | Partial |
| R-PRO-08 | The event types listed in the protocol (21 at minimum) MUST be supported. | §7 | MUST | None |
| R-PRO-09 | `CHECKPOINT_CREATED` MUST NOT embed the root or signature of a checkpoint whose root includes that same event. Checkpoint publication MUST be protocol metadata outside the event stream. | §7 | MUST | None |

### CRY: Merkle tree, checkpoints and signatures

Details are in `PROTOCOL.md` sections 8 to 10.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-CRY-01 | One exact Merkle construction MUST be chosen (RFC 6962 or RFC 9162). A custom hybrid MUST NOT be called simply "RFC-compliant". | §8 | MUST | None |
| R-CRY-02 | The protocol MUST define empty-tree behavior, tree shape, leaf and node hashing, inclusion proofs, consistency proofs, stream identity, genesis checkpoint and malformed-proof rejection. | §8 | MUST | None |
| R-CRY-03 | Checkpoints MUST be domain-separated Ed25519 signatures over a canonical payload containing at least protocol version, stream or run identity, tree size, root hash, previous checkpoint hash, key ID and creation time. | §8 | MUST | Partial |
| R-CRY-04 | A timestamp MUST be treated as a claim unless backed by a separately verified trusted timestamp service. | §8 | MUST | Partial |
| R-CRY-05 | Key rotation MUST include old-key authorization, new-key activation and a verifiable transition record. Verification keys MUST be distributed out of band or through an independently trusted key manifest. | §8 | MUST | None |
| R-CRY-06 | The signer, CLI verifier and WASM verifier MUST share one Rust core. Wrappers MUST NOT reimplement cryptographic rules independently. | §8 | MUST | None |

### SIG: Signer and anti-rollback

Details are in `PROTOCOL.md` section 11.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-SIG-01 | The signer MUST run as a separate process or container with a dedicated persistent key volume. Private keys MUST NOT be mounted into FastAPI, Litestar, worker, dashboard or other general containers. | §4, §9 | MUST | Partial |
| R-SIG-02 | The signer MUST have no general database credentials and MUST expose only a narrow authenticated API. | §4, §9 | MUST | None |
| R-SIG-03 | A signing request MUST carry the stream identity, the previous signed checkpoint, and the canonical bytes of the new events. The signer MUST compute the new root itself from a stored Merkle frontier and MUST NOT sign a root or list of leaf hashes supplied by the caller (D-12). | §9 (changed by D-12) | MUST | None |
| R-SIG-04 | The signer MUST validate that each event is strict canonical JSON, has the right protocol version and run ID, has a consecutive sequence starting at its own tree size, has a known event type and is within size limits, and that nothing follows `RUN_FINISHED`. | §9 (D-12) | MUST | None |
| R-SIG-05 | The signer MUST authenticate the calling ingestion service (`caller_attestation`) and MUST reject a request whose `expected_root`, if given, differs from the root it computed (`ROOT_MISMATCH`). | §9 (D-12) | MUST | None |
| R-SIG-06 | Documentation MUST state that the signer proves well-formed, ordered events extending its previous state, not that the events are true. | §9 (D-12) | MUST | None |
| R-SIG-07 | The signer MUST verify the proposed tree extends its own last accepted checkpoint, and MUST reject smaller or equal sizes unless returning an identical checkpoint idempotently. | §9 | MUST | None |
| R-SIG-08 | The signer MUST reject non-extending roots, forked histories, unknown streams without a valid genesis, malformed proofs, duplicate or missing sequences and invalid authorization. | §9 | MUST | None |
| R-SIG-09 | The signer MUST persist new state durably before returning a successful signature. | §9 | MUST | None |
| R-SIG-10 | The signer MUST fail closed on corrupt state and require an explicit recovery ceremony. It MUST NOT silently reset. | §9 | MUST | None |
| R-SIG-11 | The signer MUST rate-limit and audit signing requests. | §9 | MUST | None |
| R-SIG-12 | The signer MUST keep a hash-chained append-only state log (stream ID, tree size, root, checkpoint hash, key ID, transition metadata). | §9 | MUST | None |
| R-SIG-13 | Keys SHOULD be generated offline where feasible, with an encrypted offline backup and documented, tested restore and rotation procedures. | §9 | SHOULD | None |

### WIT: Witnesses and anchors

Details are in `PROTOCOL.md` sections 12 and 13.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-WIT-01 | The witness quorum MUST be defined unambiguously. This design uses 2-of-3 independent witnesses in addition to the primary signer (decision D-02). | §10 | MUST | None |
| R-WIT-02 | Each witness MUST have separate key material and persistent anti-rollback state. | §10 | MUST | None |
| R-WIT-03 | The signer and every witness MUST carry a `failure_domain` label. Witnesses that share a domain with each other or with the signer MUST make `witness_quorum` report `NOT_INDEPENDENT`, never `PASS` (D-15). | §10 (D-15) | MUST | None |
| R-WIT-04 | Witnesses and anchors MUST cover global checkpoints (D-10). | ext (D-10) | MUST | None |
| R-WIT-05 | The minimum anchor SHOULD be an append-only file in a public Git repository with one line per global checkpoint. An anchor in the same administrator's repository as the signer MUST be reported `NOT_INDEPENDENT`. | ext (D-15) | SHOULD | None |
| R-WIT-06 | Witnesses MUST independently verify checkpoint extension before signing. They MUST NOT cosign blindly. | §10 | MUST | None |
| R-WIT-07 | `LOCAL_ONLY` MUST NOT claim external anti-rollback protection against full host rollback. | §10 | MUST | Partial |
| R-WIT-08 | `CONNECTED_EVIDENCE` MAY publish checkpoint digests to a public Git repository, another administrator's repository, or a verified transparency or timestamp service. Availability and terms are external dependencies. | §10 | MAY | Partial |
| R-WIT-09 | Git commit timestamps MUST NOT be treated as trusted timestamps. | §10 | MUST | Partial |
| R-WIT-10 | Anchors MUST be out-of-band metadata, not ordinary run events. | §10 | MUST | Partial |

### DAT: Data and artifact storage

Details are in `DESIGN.md` sections 9 and 10.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-DAT-01 | PostgreSQL MUST hold transactional run state, users, policies, event metadata, idempotency, workflow references, checkpoints and signer and witness records. TimescaleDB hypertables MUST be used only for suitable time-series telemetry, not automatically for the core event ledger. | §11 | MUST | None |
| R-DAT-02 | The logical tables MUST exist: `runs`, `run_state_transitions`, `event_stream_heads`, `events`, `event_idempotency`, `artifacts`, `policies` / `policy_versions`, `ml_assessments`, `checkpoints`, `witness_signatures`, `anchor_publications`, `workflow_outbox`. | §11 | MUST | Partial |
| R-DAT-03 | There MUST be one serialized writer per run. The ingestion service MUST lock `event_stream_heads` with `SELECT ... FOR UPDATE` in the same transaction that commits the next sequence and event. | §11 | MUST | None |
| R-DAT-04 | The event row, the head update and the outbox entry MUST commit atomically. | §11 | MUST | Partial |
| R-DAT-05 | SSE MUST read only committed events and MUST support replay with `Last-Event-ID`. | §11 | MUST | None |
| R-DAT-06 | Application roles MUST be least-privilege and the ingestion service MUST own normal committed event writes. The design MUST NOT claim this stops a database administrator. | §11 | MUST | None |
| R-DAT-07 | The TimescaleDB edition, licensing, index and constraint behavior SHOULD be reviewed before adopting hypertables. The protocol ledger MUST stay in ordinary tables if an extension constraint complicates required uniqueness. | §11 | SHOULD | None |
| R-DAT-08 | Artifacts MUST be stored in MinIO under object keys derived from their SHA-256 digest, with metadata and digest in PostgreSQL. | §11 | MUST | Partial |
| R-DAT-09 | The artifact digest MUST be verified after upload and before export or download. | §11 | MUST | Partial |
| R-DAT-10 | Versioning and object-lock features SHOULD be used only after validating edition and licensing. They MUST NOT be assumed to protect against host administrators. | §11 | SHOULD | None |
| R-DAT-11 | Uploads MUST go through a single designated artifact component. Workers MUST NOT overwrite arbitrary objects or mutate committed artifact metadata. | §11 | MUST | None |
| R-DAT-12 | Uploads MUST use a temporary object, checksum verification and atomic metadata finalization. Abandoned uploads MUST be cleaned up. | §11 | MUST | Partial |
| R-DAT-13 | IPFS MAY be used for pinning or distribution. A CID MUST NOT substitute for the signed receipt, and the system MUST work without IPFS. | §11 | MAY | None |

### SVC: Services and trust boundaries

Details are in `DESIGN.md` sections 5 and 6.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-SVC-01 | The browser UI MUST be treated as an untrusted presentation layer. It MUST NOT decide whether a receipt is valid. | §4 | MUST | Partial |
| R-SVC-02 | The FastAPI control plane MUST handle authentication and authorization, run creation and cancellation, policy version selection, workflow start and query, receipt export and verification job endpoints, and budget and TinyFish opt-in controls. It MUST NOT have access to signer private keys. | §4, §12 | MUST | Partial |
| R-SVC-03 | The Litestar ingestion service MUST handle schema and size validation, authenticated adapter intake, idempotency, sequence assignment, transactional commit with outbox, SSE with replay, rate limits and backpressure. It MUST be the sole normal writer of committed event rows and MUST NOT access signing keys. | §4, §12 | MUST | None |
| R-SVC-04 | Litestar throughput SHOULD be benchmarked before it is tuned. | §2 | SHOULD | None |
| R-SVC-05 | The worker and adapters MUST be treated as untrusted for ledger integrity. They MUST NOT rewrite committed events or call the signer with arbitrary roots. | §4 | MUST | Partial |
| R-SVC-06 | Temporal activities MUST be idempotent. Ambiguous irreversible outcomes MUST be reconciled, not blindly retried. | §12 | MUST | None |

### ADP: Execution adapters

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-ADP-01 | The system MUST provide an adapter interface with ReplayAdapter (first and default), local Playwright, and optional TinyFish. | §2, §12 | MUST | None |
| R-ADP-02 | Every adapter MUST return a normalized result with `adapter_name`, `adapter_version`, `execution_id`, `requested_coverage`, `observed_coverage`, `started_at`, `finished_at`, `status`, `steps[]`, `artifacts[]`, `errors[]`, `external_usage` and `provenance`. | §12 | MUST | None |
| R-ADP-03 | The schema MUST distinguish `reported_by_adapter`, `observed_by_local_gateway` and `verified_by_black_box`. | §12 | MUST | None |
| R-ADP-04 | ReplayAdapter MUST be deterministic. | §2, §20 | MUST | None |

### TFY: TinyFish and the $15 credit plan

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-TFY-01 | TinyFish MUST be an optional external adapter and MUST require explicit opt-in. | §2, §13 | MUST | Partial |
| R-TFY-02 | Search/Fetch and Agent MUST be supported through separate adapter methods, and actual provider usage MUST be reported where available. | §13 | SHOULD | None |
| R-TFY-03 | A hard project-wide spend or credit ceiling MUST be set from actual provider metering, not guessed request counts. | §13 | MUST | None |
| R-TFY-04 | Before each run the system MUST require opt-in, estimate usage if the API supports it, and check remaining credits if the provider exposes them. | §13 | MUST | None |
| R-TFY-05 | Optional calls MUST stop at the configured reserve threshold, with no silent fallback to a paid operation. | §13 | MUST | None |
| R-TFY-06 | The system MUST record operation type, provider execution ID, metering data returned by the API, and the time usage was observed. | §13 | MUST | None |
| R-TFY-07 | The adapter MUST handle quota exhaustion gracefully. | §13 | MUST | None |
| R-TFY-08 | A capability spike MUST cover per-step records, artifact availability and retention, timestamp semantics, errors and cancellation, actual credit use, quotas, pre-execution gating, and evidence-retention terms, before TinyFish coverage is classified. | §13 | MUST | None |
| R-TFY-09 | The initial $15 allocation SHOULD be Agent tests $6, Search/Fetch tests $3, evidence validation and reruns $3, reserve $3. These are planning limits, not provider price estimates. | §13 | SHOULD | None |
| R-TFY-10 | Broad crawls and uncontrolled agent loops MUST NOT be run. | §13 | MUST | Partial |

### POL: Deterministic policy engine

Details are in `DESIGN.md` section 12.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-POL-01 | Policy decisions MUST be deterministic, versioned, and recorded separately from ML assessments. | §14 | MUST | Partial |
| R-POL-02 | The policy engine MUST support allowlists and denylists, action constraints, domain restrictions, rate limits, human approval gates and explicit high-risk action handling. | §14 | MUST | Partial |
| R-POL-03 | Each decision MUST record policy ID and version, input digest, decision, reason codes and approval reference. | §14 | MUST | Partial |
| R-POL-04 | The policy engine MUST be in the execution path for `STEP_GATED`. | §14 | MUST | Partial |
| R-POL-05 | ML scores MUST NOT override a deterministic deny and MUST NOT authorize an action. | §14 | MUST | None |
| R-POL-06 | Each run MUST reference the exact policy version it used. Policy changes MUST be versioned. | §14 | MUST | None |

### SEM: Semantic invariant monitor (Oathkeeper-inspired)

The Oathkeeper in this document is the research approach, not Ory Oathkeeper.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-SEM-01 | The monitor MUST start with explicit deterministic invariants authored from task requirements. | §15A.A | MUST | None |
| R-SEM-02 | Each invariant MUST have regression scenarios with known-good and known-bad traces. | §15A.A | MUST | None |
| R-SEM-03 | Invariants MUST be evaluated against live traces and MUST point to the exact event range that failed. | §15A.A | MUST | None |
| R-SEM-04 | Missing or unobserved steps MUST be `UNKNOWN`, never a pass. | §15A.A | MUST | None |
| R-SEM-05 | Mining candidate invariants from paired regression traces MAY be tried later, and inferred rules MUST be human-reviewed before they are enabled. | §15A.A | MAY | None |
| R-SEM-06 | The monitor MUST emit `SEMANTIC_INVARIANT_CHECKED` and `SEMANTIC_VIOLATION_DETECTED` events with invariant ID and version, severity, evidence event IDs, confidence or explanation, and status. | §15A.A | MUST | None |
| R-SEM-07 | The monitor MUST NOT grant permissions. A finding MAY trigger a policy-defined escalation only. | §15A.A | MUST | None |

### ART: Artifact provenance (HashCam-style)

This is cryptographic integrity, not ML.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-ART-01 | For each artifact the system MUST record run ID, event ID, adapter, capture method, MIME type, size and a timestamp claim. | §15A.B | MUST | Partial |
| R-ART-02 | Each artifact MUST be hashed with SHA-256 over its exact bytes and stored content-addressed, and the digest MUST be verified after upload and on export. | §15A.B | MUST | Partial |
| R-ART-03 | A canonical manifest entry with the artifact digest and a reference to the previous entry MUST be appended. | §15A.B | MUST | None |
| R-ART-04 | The manifest head MUST be bound into the signed checkpoint and the exported receipt. | §15A.B | MUST | None |
| R-ART-05 | Artifact digests and manifest linkage MUST be verifiable offline. | §15A.B | MUST | None |
| R-ART-06 | The artifact manifest MUST stay separate from the event Merkle tree. The checkpoint references both. | §15A.B | MUST | None |
| R-ART-07 | The system MUST NOT claim a hash proves the capture is genuine or the page truthful, MUST NOT claim absolute immutability, and MUST label local timestamps as claims. | §15A.B | MUST | Partial |

### PIG: Prompt-injection guard (Prompt Chainmail-inspired)

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-PIG-01 | A layered guard MUST screen untrusted page text, fetched documents, accessibility-tree content and tool outputs before they reach the agent as context. | §15A.C | MUST | None |
| R-PIG-02 | The guard MUST preserve a digest or reference to the original input and apply size limits. | §15A.C | MUST | None |
| R-PIG-03 | The guard MUST run deterministic checks for common injection patterns, role confusion, hidden instructions and tool-use hijacking. | §15A.C | MUST | None |
| R-PIG-04 | The guard MAY run an optional local ONNX classifier. It MUST be off by default; deterministic checks are the default, and receipts record `classifier_available = false` while it is off (D-17). | §15A.C (D-17) | MAY | None |
| R-PIG-05 | The guard MUST emit `ALLOW`, `FLAG_FOR_REVIEW` or `BLOCK_BY_POLICY` as a signal to the policy gateway, not as an authorization decision. | §15A.C | MUST | None |
| R-PIG-06 | The guard MUST record detector or model version, score, reason codes, source digest and coverage. | §15A.C | MUST | None |
| R-PIG-07 | If the classifier is unavailable the guard MUST fall back to deterministic checks and record that classifier coverage was unavailable. | §15A.C | MUST | None |
| R-PIG-08 | Before copying, vendoring or shipping Prompt Chainmail code or models, the exact revision, model artifact, license (its repository lists Business Source License 1.1) and release status MUST be inspected. It is a candidate reference, not an approved dependency. | §15A.C | MUST | None |
| R-PIG-09 | The guard MUST be evaluated against benign hard negatives and attacks across supported languages and content types, with false positives and false negatives reported. | §15A.C | MUST | None |
| R-PIG-10 | The guard MUST NOT be described as a complete prompt-injection solution. | §15A.C | MUST | Partial |

### ANO: Behavior anomaly auditor

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-ANO-01 | The anomaly auditor is a stretch goal. It MUST remain advisory, and the demo and the acceptance criterion MUST NOT depend on it (D-18). | §15 (D-18) | MUST | None |
| R-ANO-02 | The system SHOULD offer replay drift: rerun or replay a task and report differences in actions, hosts and outcome as an advisory `BEHAVIOR_ANOMALY_ASSESSMENT` (D-19). | ext (D-19) | SHOULD | None |
| R-ANO-03 | The auditor MUST start with interpretable baselines before complex models. | §15 | MUST | None |
| R-ANO-04 | Candidate features SHOULD include step and action count patterns, loops and retry bursts, dwell-time distributions, navigation/reading/action ratios, action n-grams, and outcome and error patterns that are not policy-derived labels. | §15 | SHOULD | None |
| R-ANO-05 | "Policy violation" and "off-allowlist" MUST NOT be model input features. | §15 | MUST | None |
| R-ANO-06 | Evaluation SHOULD compare deterministic rules, Isolation Forest, and a supervised classifier only if labeled data exists. | §15 | SHOULD | None |
| R-ANO-07 | Data MUST be split by scenario family and time, not by random rows from one execution family. | §15 | MUST | None |
| R-ANO-08 | The evaluation MUST report precision, recall, false-positive rate, calibration where applicable, and performance by scenario. | §15 | MUST | None |
| R-ANO-09 | Unsupervised anomaly scores MUST NOT be described as probabilities unless calibrated. | §15 | MUST | None |
| R-ANO-10 | Receipts MUST carry only model, version and feature-schema identifiers and metadata. Executable (pickled) models MUST NOT be embedded. | §15 | MUST | None |
| R-ANO-11 | ML failure MUST NOT prevent cryptographic verification or change authorization decisions. | §15 | MUST | None |

### REC: Receipts and the verifier

Details are in `PROTOCOL.md` sections 15 and 16.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-REC-01 | A receipt MUST contain protocol and schema versions, run ID, adapter identity and version, declared and observed coverage, canonical events or event hashes with proofs, checkpoints with signer key ID and signatures, artifact digests and provenance, policy version and decisions, and (when present) semantic, prompt-security, anomaly, manifest, witness and anchor data, plus exporter version. | §16 | MUST | None |
| R-REC-02 | The verifier MUST output separate dimensions, not one opaque boolean: `evidence_integrity`, `checkpoint_signatures`, `consistency`, `artifact_availability`, `witness_quorum`, `anchor_match`, `observation_coverage`, `policy_assessment`, `semantic_assessment`, `prompt_security_assessment`, `behavior_anomaly_assessment`, `artifact_manifest_integrity`, `ml_assessment` (aggregate display only), `execution_outcome`. | §16 | MUST | Partial |
| R-REC-03 | The overall result MUST be one of `VALID`, `INVALID`, `INCOMPLETE`, `UNSUPPORTED`, `PARTIAL` with the meanings defined in the protocol. | §16 | MUST | None |
| R-REC-04 | Required and optional dimensions MUST be defined per profile. `INCOMPLETE` means a required dimension lacks evidence; `PARTIAL` means only an optional dimension is unavailable or `NOT_INDEPENDENT` (D-19). | §16 (D-19) | MUST | None |
| R-REC-05 | The verifier MUST add the dimensions `global_log_inclusion` (D-10) and `mandate_compliance` (D-16, `NOT_APPLICABLE` without a mandate), and MUST support the value `NOT_INDEPENDENT` for `witness_quorum` and `anchor_match`. | ext (D-10, D-15, D-16) | MUST | None |
| R-REC-06 | Documentation and UI MUST state that a valid signature does not mean the task was safe, correct, authorized or executed as claimed. | §16 | MUST | Partial |
| R-REC-07 | One Rust verification core MUST serve both CLI and WASM. The CLI MUST be the independent reference implementation and the offline verifier MUST remain authoritative. | §2, §17 | MUST | None |
| R-REC-08 | The WASM verifier MUST enforce size limits, path-traversal defenses, bounded decompression, safe parsing, and rejection of unknown critical fields. | §17 | MUST | None |
| R-REC-09 | Dependencies SHOULD be pinned and builds SHOULD be reproducible where practical. | §17 | SHOULD | Partial |
| R-REC-10 | Because Subresource Integrity cannot defeat a compromised page, a separately downloadable CLI or offline verifier build MUST be provided, with its digest and key published through an independent channel. | §17 | MUST | None |
| R-REC-11 | Test vectors MUST cover valid receipts, modified events, invalid signatures, invalid consistency proofs, missing artifacts, unknown versions, truncated files and malformed input. | §17 | MUST | None |

### UI: User interface

Details are in `DESIGN.md` section 16.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-UI-01 | The UI MUST provide a dashboard, run explorer, policy view and receipt viewer, built with Next.js, React, TypeScript, Tailwind CSS and shadcn/ui. | §2 | MUST | Partial |
| R-UI-02 | The UI MUST show the five assessment channels (policy, semantic, prompt security, behavior anomaly, evidence integrity) separately, with provenance and coverage. | §15A.D, §21 | MUST | None |
| R-UI-03 | Live updates MUST use Server-Sent Events with replay through event IDs. | §2 | MUST | None |
| R-UI-04 | The browser verifier (WASM) MUST NOT be the only way to check a receipt. | §5 | MUST | None |
| R-UI-05 | An anomaly, an injection score or a valid hash MUST NOT be presented as proof of malice, attack success or truthfulness. | §15A.D | MUST | Partial |

### OPS: Deployment and operations

Details are in `DESIGN.md` section 17.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-OPS-01 | Docker Compose MUST provide profiles `core`, `replay`, `playwright`, `tinyfish`, `ipfs`, `llm` and `testing`. | §19 | MUST | Partial |
| R-OPS-02 | Images SHOULD be pinned by immutable digest where feasible. Services MUST have health checks, startup ordering, migrations, resource limits, non-root users and least-privilege credentials. | §19 | MUST | Partial |
| R-OPS-03 | The signer key volume MUST be separate and MUST NOT be mounted into other services. Signer network ingress MUST be restricted to authenticated ingestion and checkpoint requests. | §19 | MUST | Partial |
| R-OPS-04 | PostgreSQL, MinIO, Temporal and signer ports MUST NOT be exposed publicly by default. | §19 | MUST | Partial |
| R-OPS-05 | Secrets MUST be kept in local secret files or a suitable secret mechanism. API keys MUST NOT be committed. | §19 | MUST | Partial |
| R-OPS-06 | PostgreSQL, MinIO artifacts, signer state, keys and verifier public-key manifests MUST be backed up, and restore MUST be tested. | §19 | MUST | None |
| R-OPS-07 | The system MUST have retention limits, log redaction, disk-space alerts and safe shutdown handling. | §19 | MUST | Partial |
| R-OPS-08 | The documentation MUST state which optional profiles need internet access. | §19 | MUST | None |

### TST: Test and release gates

A capability MUST NOT be labeled `TESTED` until CI or a reproducible local test proves it (v9 §20).

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-TST-01 | Protocol and crypto tests MUST cover JCS vectors and rejections, hash and domain-separation vectors, inclusion and consistency proofs for empty, single, power-of-two and irregular sizes, signatures, key rotation, genesis, malformed input, and Rust CLI versus WASM agreement. | §20 | MUST | Partial |
| R-TST-02 | Storage and concurrency tests MUST cover concurrent writers for one run, duplicate delivery, stale worker fencing, crashes between upload, metadata commit, event commit and checkpoint, database restore and rollback, and artifact corruption or loss. | §20 | MUST | None |
| R-TST-03 | Signer and witness tests MUST cover arbitrary-root attempts, missing or duplicate sequences, forks, signer state corruption and recovery, quorum with unavailable or colluding witnesses, and accurate documentation of independent deployment. | §20 | MUST | None |
| R-TST-04 | Adapter and ML tests MUST cover ReplayAdapter determinism, Playwright coverage and bypass, TinyFish quota exhaustion, timeout, malformed response and provenance, no paid fallback when the budget is exhausted, and ML baseline comparison with false-positive reporting. | §20 | MUST | None |
| R-TST-05 | Security and deployment tests MUST cover authorization boundaries and tenant isolation before multi-tenancy, SSRF and untrusted URL handling, upload, path and decompression safeguards, secret scanning, dependency audit, image pinning, backup and restore, and Compose start and clean shutdown from a fresh checkout. | §20 | MUST | None |

### CLM: Claims ledger and acceptance

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-CLM-01 | Every README and demo claim MUST carry exactly one status: `SPECIFIED`, `IMPLEMENTED`, `TESTED`, `MEASURED` or `UNVERIFIED`. | §22 | MUST | Partial |
| R-CLM-02 | Initially all implementation and security claims MUST be `SPECIFIED` or `UNVERIFIED`, not `TESTED`. | §22 | MUST | Partial |
| R-CLM-03 | The project MUST NOT claim that the signer prevents forks, the system detects rollback, Playwright is fully gated, TinyFish exposes step-level evidence, semantic invariants catch real violations, the prompt classifier is production-ready, ML beats a baseline, artifact capture is genuine, or CLI and WASM agree, until the matching tests and evidence exist. | §22 | MUST | Partial |
| R-CLM-04 | Acceptance: a fresh local deployment MUST be able to run a replay scenario, run deterministic policy and semantic checks, hash-link a captured artifact, record canonical events, create and verify a signed checkpoint, export a receipt, detect event and artifact tampering, and explain coverage limitations, with no paid service or external ML API. | §23 | MUST | None |

### GLB: Global log of run roots (extension, D-10)

Details are in `PROTOCOL.md` section 8.5 and `DESIGN.md` section 11.4.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-GLB-01 | A global log (stream `global`) MUST append the final checkpoint of every finalized run, using the same tree rules as run streams. | ext (D-10) | MUST | None |
| R-GLB-02 | The signer MUST append a run root only for a checkpoint present in its own state log. | ext (D-10) | MUST | None |
| R-GLB-03 | A run MUST NOT reach `EXPORTED` before its root is in the global log and a global checkpoint covers it. | ext (D-10) | MUST | None |
| R-GLB-04 | Receipts MUST carry the run's global inclusion proof and the global checkpoint chain, and the verifier MUST check them. | ext (D-10) | MUST | None |
| R-GLB-05 | The CLI MUST provide `abb verify-global`, which recomputes the global root from the run roots in the database and compares it with the latest witnessed or anchored global checkpoint, so a deleted or altered run is detected. | ext (D-10) | MUST | None |
| R-GLB-06 | Documentation MUST state the limits: a run deleted before it is appended, or a rollback that also removes every witness and anchor, is not detected. | ext (D-10) | MUST | None |

### CMT: Salted field commitments (extension, D-11)

Details are in `PROTOCOL.md` section 5.5 and `DESIGN.md` section 9.1.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-CMT-01 | Sensitive payload fields chosen by redaction policy MUST be replaced by salted commitments before canonicalization. Clear values MUST NOT be written to the ledger. | ext (D-11) | MUST | Partial |
| R-CMT-02 | A commitment MUST be `SHA-256("ABB1-FIELD" || 0x00 || salt || JCS(value))` with a 16-byte CSPRNG salt that is unique per field per event. | ext (D-11) | MUST | None |
| R-CMT-03 | Salts and clear values MUST be kept in a restricted store outside the ledger. Deleting a salt (crypto-shredding) MUST NOT affect the validity of the Merkle tree, inclusion proofs or signatures. | ext (D-11) | MUST | None |
| R-CMT-04 | Receipts MAY include `disclosures`. The verifier MUST recompute each disclosed commitment and fail on mismatch. | ext (D-11) | MUST | None |
| R-CMT-05 | A dimension that needs an undisclosed field MUST report `UNKNOWN`, never `PASS`. | ext (D-11) | MUST | None |
| R-CMT-06 | Policy MUST NOT hide a field that a required deterministic check needs in order to run offline. | ext (D-11) | MUST | None |
| R-CMT-07 | Documentation MUST state that hiding a value does not hide the event's existence, type, timing claim or size class. | ext (D-11) | MUST | None |

### APR: Signed approvals and mandate (extension, D-16)

Details are in `PROTOCOL.md` sections 5.6 and 5.7 and `DESIGN.md` section 11.5.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-APR-01 | A human approval MUST be an Ed25519 signature over an approval statement (`ABB1-APPROVAL`) made on the approver's own device. The control plane MUST NOT hold approver private keys. | ext (D-16) | MUST | Partial |
| R-APR-02 | `HUMAN_APPROVAL_GRANTED` and `HUMAN_APPROVAL_DENIED` MUST carry `approver_key_id` and `approval_signature`, and the verifier MUST check them against the key manifest (role `approver`). | ext (D-16) | MUST | None |
| R-APR-03 | The approval's `summary_digest` MUST equal the digest of what the human was shown and MUST match the matching `HUMAN_APPROVAL_REQUESTED`. | ext (D-16) | MUST | None |
| R-APR-04 | An approval MUST match the action ID and MUST NOT be used after `expires_at`. A missing or invalid signature on a required approval MUST make `policy_assessment` `FAIL`. | ext (D-16) | MUST | None |
| R-APR-05 | A run MAY carry a signed mandate (allowed hosts, action types, action count, optional spend limit, validity window) referenced from `RUN_STARTED`. | ext (D-16) | MAY | None |
| R-APR-06 | When a mandate is present the gateway SHOULD enforce it as a deterministic policy input. | ext (D-16) | SHOULD | None |
| R-APR-07 | When a mandate is present the verifier MUST report `mandate_compliance` over action type, host, action count and spend, with `UNKNOWN` for anything it cannot check. | ext (D-16) | MUST | None |
| R-APR-08 | Documentation MUST state that a signed approval proves a key signed, not which human held the key. | ext (D-16) | MUST | None |

### HKC: Hackathon cut (D-13)

Details are in `DESIGN.md` sections 3.1 and 20.1. The protocol does not change; only the infrastructure does.

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-HKC-01 | The first build SHOULD use one FastAPI service that contains ingestion and SSE. A Litestar split SHOULD wait until a benchmark shows the need. | §2 (D-13) | SHOULD | Partial |
| R-HKC-02 | The ledger SHOULD run on plain PostgreSQL. TimescaleDB SHOULD be used only for telemetry, after license review. | §2 (D-13) | SHOULD | None |
| R-HKC-03 | The first build SHOULD use a Postgres lease and fencing token instead of Temporal. The same safety rules (no stale-worker commit, no blind retry) MUST still hold. | §5 (D-13) | SHOULD | None |
| R-HKC-04 | IPFS and the WASM verifier MAY be deferred. The Rust CLI stays authoritative. | §2 (D-13) | MAY | None |
| R-HKC-05 | The cut MUST keep the separate signer, the global log, a witness on a second device and a Git anchor. | ext (D-13) | MUST | None |
| R-HKC-06 | Each deferred component SHOULD sit behind an interface so full v9 can be added without a protocol change. | ext (D-13) | SHOULD | None |
| R-HKC-07 | The demo MUST show a receipt verifying, a tampered event and a tampered artifact being caught, and a deleted run being caught by `abb verify-global`. | ext (D-13) | MUST | None |

### EXT: Optional extension: human-approved payment (not in v9)

v9 does not mention payments. These requirements keep the prototype's testnet payment flow as an optional module that reuses the v9 `HUMAN_APPROVAL_*` events. They need your confirmation (decision D-08).

| ID | Requirement | v9 | Priority | Prototype |
|---|---|---|---|---|
| R-EXT-01 | The agent MUST only prepare a payment request. It MUST NOT have any function that sends money. | extension | MUST | Done |
| R-EXT-02 | A human MUST approve on a separate confirmation screen, and the recipient and amount MUST come from the stored payment row, not from agent input. (The prototype reads the amount from the stored row, but the separate confirmation screen is not built.) | extension | MUST | Partial |
| R-EXT-03 | An approved payment MUST wait a cooling period (30 seconds by default) in which it can be cancelled. | extension | MUST | Done |
| R-EXT-04 | Signing MUST use a testnet wallet only. Mainnet MUST NOT be enabled in this prototype. (The prototype only takes a signer function; no wallet exists yet.) | extension | MUST | None |
| R-EXT-05 | Each step (request, approval requested, granted or denied, cancel, dispatch) MUST be recorded as ledger events with the protocol event types. | extension | MUST | Partial |

## 4. Traceability

| Area | Protocol sections | Design sections |
|---|---|---|
| SYS | 1, 19 | 2, 18 |
| RUN | 5, 6 | 7 |
| COV | 7 | 8 |
| PRO | 3, 4, 5 | 7 |
| CRY | 8, 9, 10 | 11 |
| SIG | 11 | 11 |
| WIT | 12, 13 | 11 |
| DAT | 5.3 | 9, 10 |
| SVC | none | 5, 6 |
| ADP, TFY | 5.1, 7 | 13 |
| POL | 5.2, 14 | 12 |
| SEM, ART, PIG, ANO | 9, 14 | 14 |
| REC | 15, 16, 17 | 15 |
| UI | 14 | 16 |
| OPS | none | 17 |
| TST | 17 | 19 |
| CLM | none | 21 |
| GLB | 8.5, 10 | 11.4 |
| CMT | 5.5 | 9.1 |
| APR | 5.6, 5.7 | 11.5 |
| HKC | none | 3.1, 20.1 |
| EXT | 5.2 | 23 |

## 5. Out of scope

- Multi-tenancy (v9 §20 requires authorization and tenant isolation tests before it is enabled, so it stays off).
- Real-money payments. The optional payment extension is testnet only.
- Any claim of regulator certification or independent audit.
- Proof that an external action truly happened without trustworthy observation or independent attestation (v9 §1).
