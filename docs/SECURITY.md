# Agent Black Box: Security

**Version:** Draft 0.1
**Related:** `Agent_Black_Box_Final_Architecture_v10.md`, `DESIGN.md` (sections 5, 11, 17, 18), `PROTOCOL.md` (section 19), `ERROR_HANDLING.md`, `TESTING.md`
**Claim status:** every control below is `SPECIFIED`. None is `IMPLEMENTED` or `TESTED` for v10. The current Python prototype covers only some of them (see section 14).

---

## 1. Purpose and scope

This document says what we protect, from whom, with which controls, and what we do **not** protect against. It covers the target system (v10), not only the prototype.

The product is an **evidence and behavioral-auditing system**. A valid receipt does not mean an agent is honest, safe or correct, or that a real-world action happened (v9 §1, §18). Anyone describing the product MUST keep that wording.

## 2. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| Signer private key | Forging checkpoints | Signer key volume only |
| Witness private keys | Forging witness signatures | Each witness's own device |
| Approver private keys | Forging approvals | Approver's own device |
| Signer state log | Detects rollback and forks | Signer volume, backed up |
| Event ledger and global log | The evidence itself | PostgreSQL |
| Artifacts (screenshots, HTML, downloads) | Evidence content, may hold personal data | MinIO |
| Field salts and clear values | Hidden sensitive data | `field_disclosures` table, restricted |
| API tokens and TinyFish key | Spend, access | Secret files, never in the repo |
| Key manifest and anchors | Trust root for verifiers | Published through an independent channel |

## 3. Actors and trust

| Actor | Trust | Notes |
|---|---|---|
| Browser and UI | Untrusted presentation | Never decides if a receipt is valid |
| FastAPI control plane | Trusted for auth and orchestration | No signer or approver keys |
| Ingestion module | Trusted writer of events | Sole normal writer |
| Worker and adapters | **Untrusted for ledger integrity** | Propose events; cannot rewrite committed ones |
| Signer | Isolated | Recomputes roots, own state log |
| Database and object store | Durable, **not immutable** | A host admin can rewrite them |
| Witnesses and anchors | External, labeled by `failure_domain` | Never called independent if they share a domain |
| Approver | Human holding a key | Signature proves the key, not the person |
| Auditor | Anyone with a receipt | Verifies offline |
| Web content seen by the agent | **Hostile by default** | May carry prompt injection |

## 4. Threat model

Format: threat, what we do, what remains.

| # | Threat | Controls | Residual risk |
|---|---|---|---|
| T1 | Insider edits or deletes events in the database | Merkle tree, signed checkpoints, signer state log, global log, witnesses, anchors | Not detected if everything including all anchors is rolled back together, or if edits happen before the first checkpoint |
| T2 | Deleting a whole run | Global log; `abb verify-global` | Not detected if deleted before it is appended to the global log |
| T3 | Rollback of the whole database | Signer state, witnesses, Git anchor | A single machine with all backups rolled back is not detectable without an external anchor |
| T4 | Forged checkpoint | Signer isolation, Ed25519, key manifest from an independent channel | Signer host and all backups stolen |
| T5 | Caller tricks signer into signing a chosen root | Signer recomputes root from event bytes (D-12); rejects forks, gaps, regressions | Compromised ingestion can submit false but well-formed events |
| T6 | Worker or adapter fabricates observations | Source labels (`reported_by_adapter` vs `observed_by_local_gateway`), coverage labels, gateway bypass tests | A compromised capture host can lie before hashing |
| T7 | Agent bypasses the gateway | `STEP_GATED` only after bypass tests; dispatch needs earlier authorization; verifier check | Anything not mediated is out of scope and shown as such |
| T8 | Prompt injection through web pages | Deterministic guard as a signal; policy gateway decides; mandate limits | Not a complete solution. Novel attacks will pass |
| T9 | Forged or replayed human approval | Signed approvals, `action_id` and `summary_digest` binding, expiry | Stolen approver key; approver tricked into signing |
| T10 | Artifact substitution | Content-addressed storage, digest check on upload and export, manifest chain | Fabricated capture before hashing |
| T11 | Leak of sensitive data from the ledger | Field commitments, log redaction, restricted `field_disclosures` | Metadata (type, timing, size) stays visible |
| T12 | SSRF through untrusted URLs | Allowlist per mandate and policy, block private ranges and metadata addresses, resolve-then-check, no redirects to blocked hosts | Misconfigured allowlist |
| T13 | Malicious receipt or archive against a verifier | Size limits, bounded decompression, path traversal rejection, no nested archives, strict parsing | Parser bugs; mitigated by fuzzing |
| T14 | Stolen API token | Scoped, expiring tokens, hashed at rest, rate limits, audit log | Token used before revoked |
| T15 | Cost abuse of TinyFish | Opt-in, hard budget guard, reserve threshold, no paid fallback | Provider metering differs from expectations |
| T16 | Dependency or image compromise | Pinned versions and digests, audit, secret scanning, non-root images | Zero-day in a pinned version |
| T17 | Replay of old events or receipts | Unique `(run_id, sequence)`, idempotency keys, fencing tokens, checkpoint chain | Replay of an old but valid receipt is still a valid old receipt |
| T18 | Denial of service on ingestion or signer | Rate limits, size limits, backpressure, signer fail-closed | Availability is not guaranteed in v10 |
| T19 | Fake timestamps | Timestamps labeled `claimed` unless trusted timestamp evidence is attached | No trusted time source by default |
| T20 | Colluding witnesses | Independence labels, `NOT_INDEPENDENT` result | Real collusion of all parties |

## 5. Authentication and authorization

**Roles** (proposed):

| Role | Can do |
|---|---|
| `admin` | Manage users, tokens, policies, key manifest entries |
| `operator` | Create and cancel runs, view runs, export receipts |
| `adapter` | Submit events and artifacts for runs it owns, nothing else |
| `approver` | Sign approvals for actions assigned to it |
| `auditor` | Read-only access to runs, receipts and verification results |

Rules:

- Every API call is authenticated. There is no anonymous write path.
- Tokens are random, 256 bits, scoped to a role and optionally to a run, with an expiry. Only a hash is stored.
- The `adapter` token for a run cannot read other runs or call the signer.
- The signer accepts only the ingestion service, authenticated by a key (`caller_attestation`) and network rules.
- The control plane never holds signer, witness or approver private keys.
- Multi-tenancy is **off** until authorization and tenant-isolation tests exist (v9 §20).
- The prototype has no real user login; `approved_by` is only a name (see section 14).

## 6. Key management

| Key | Generated | Stored | Backup | Rotation |
|---|---|---|---|---|
| Signer (Ed25519) | Offline where feasible | Dedicated volume, mode 0400, never mounted elsewhere | Encrypted offline copy | Transition record signed by old and new key (`PROTOCOL.md` 10.5) |
| Witness | On its own device | Its own volume | Its own backup | Same transition rule |
| Approver | On the approver's device | Device keystore | Approver's responsibility | Key manifest update |
| Ingestion caller key | At deploy | Secret file | With secrets | Rotate with deploy |

- Public keys are published in the **key manifest** through a channel independent of receipts.
- **Compromise procedure:** stop signing, mark the key `revoked` in the key manifest with the last trusted checkpoint, rotate, publish the new manifest, and tell verifiers that checkpoints after the last trusted one are suspect.
- **Recovery ceremony:** if signer state is corrupt, the signer refuses to sign. Recovery restores state from backup and records the event; it never silently resets.
- Restore of keys and state MUST be tested before any pilot.

## 7. Secrets

- Secrets live in Docker secrets or local secret files. They are never committed, never baked into images, never printed.
- `secrets/` is excluded from the image build context with `.dockerignore` (a known gap in the prototype, see section 14).
- The TinyFish key comes from an environment variable or secret file and is never logged or written to a receipt.
- Secret scanning runs in CI and as a pre-commit check.
- Logs redact tokens, keys, `Authorization` headers and any field marked sensitive by policy.

## 8. Input handling

| Input | Rule |
|---|---|
| Event JSON | Strict canonical JSON: integers only, no duplicate keys, valid UTF-8, size and depth limits (`PROTOCOL.md` 3) |
| Untrusted page text and tool output | Size-limited, digest kept, run through the guard before reaching the agent |
| URLs | Parse, normalize, check against allowlist and mandate, block private, loopback, link-local and cloud metadata addresses, re-check after redirects and DNS resolution |
| Uploads | Temporary location, checksum, media-type check, size cap, atomic finalize, cleanup of abandoned uploads |
| Receipts and archives | Size cap, bounded decompression ratio, path traversal rejection, no nested archives, reject unknown critical fields |
| SQL | Parameterized queries only; no string-built SQL |
| Rendering in the UI | Escape everything from events and pages; never render page HTML inside the dashboard origin |

## 9. Prompt-injection and ML safety

- Guard and anomaly output are **signals**. Only deterministic policy can block or authorize.
- The guard defaults to deterministic checks. The ONNX classifier is off until a license and quality review (D-17).
- No pickled or executable model files in receipts. Only model identifiers, versions and scores.
- ML failure never blocks cryptographic verification or changes an authorization decision.
- Policy outcomes ("off-allowlist") are never used as anomaly model features.

## 10. Privacy and data protection

- Sensitive fields are stored as salted commitments; clear values and salts live in a restricted table (D-11).
- Deleting a salt is crypto-shredding. Proofs stay valid.
- Retention limits apply to artifacts and `field_disclosures`. Defaults are not set yet.
- Hiding a value does not hide the event's existence, type, timing or size. Say so in customer-facing text.
- Legal and regulatory fit (for example data-protection law) is **not assessed** here and needs review before a real pilot.

## 11. Infrastructure hardening

- Pin images by digest where feasible; non-root users; read-only root filesystems where possible; dropped capabilities; resource limits.
- PostgreSQL, MinIO, Temporal (when used) and the signer are not exposed publicly. The signer listens on an internal network only.
- Separate Docker networks: `public` (UI and API), `internal` (database, MinIO), `signer` (ingestion and signer only), and `agent` (adapters, no route to the database or signer).
- Least-privilege database roles: the ingestion role can insert events but not update or delete; the signer has no database role; the read role is read-only (`DATABASE_AND_API_CONTRACTS.md`).
- Backups: PostgreSQL, MinIO, signer state, keys and key manifests; restore is tested.
- Disk-space alerts and safe shutdown so a full disk does not corrupt signer state.

### Local pages, graph, collector and payments (as built)

| Part | Control | Test |
|---|---|---|
| Dashboard (`services/dashboard/`) | Binds `127.0.0.1` only; serves receipts only from the folder it was started with; strict `Content-Security-Policy` (no inline script or style, no outside host); no access log; errors never carry a path, trace or receipt text; the verdict is `abb verify --json` passed through | `tests/ui/test_dashboard.py` |
| Run console (`--enable-runs`, off by default) | A human starts every run and repeats the worst-case cost; random per-server token, loopback `Host`, same-origin `Origin`; only the policy's hosts; one run at a time; timeout; the API key is inherited by the child process, never read, sent or logged | `tests/ui/test_run_console.py` |
| Graph (`services/graph/`) | The store accepts only a loopback address; every value is a query parameter; labels and relations come from fixed lists; the graph is a picture, never a verdict. `GET /api/graph` **writes** the run's graph to FalkorDB when one is connected | `tests/graph/test_graph.py` |
| Endpoint collector (`endpoint/collector.py`) | Opt-in; watches one folder you name; records file name, size, hour and (Windows) source address; never file contents, folder paths, command lines or browser history; writes a JSON-lines file you can read first | `tests/endpoint/test_collector.py` |
| Payments (`adapters/payments/`) | A key without a test prefix is refused before any request; every reply must say `livemode: false`; a hard ceiling no policy can raise; idempotency keys; the key is never printed or stored | `tests/adapter/test_payments.py` |
| S3 artifact store | Plain `http://` only for loopback; credentials only in the signed header; every read is re-verified | `tests/contract/test_s3_store.py` |

Gaps in this table are listed in section 16 (read routes without a `Host` check; a FalkorDB without a password).

## 12. Supply chain

- Lock files committed; versions pinned; dependency audit in CI (`pip-audit`, `cargo audit`, `npm audit`).
- Review licenses before adding a dependency (TimescaleDB edition, MinIO edition, Prompt Chainmail BSL 1.1).
- Reproducible builds for the Rust verifier where practical; publish its digest through an independent channel.
- SBOM generation in the release step.
- Content from cloned third-party repositories (skills, templates) is treated as untrusted data and is not executed without review.

## 13. Detection, logging and incident response

- An audit log records authentication events, token use, policy changes, signing requests, key operations and exports.
- Logs go to the host and are redacted. They are not part of the evidence ledger.
- **Incident steps:** contain (revoke tokens, stop signing if keys are in doubt), preserve (copy database, MinIO and signer state read-only), verify (run the verifier and `abb verify-global` against the latest anchor), rotate (keys and secrets), notify (customers and witnesses as agreed), review (write a postmortem).
- **Vulnerability reporting:** a security contact and disclosure policy MUST be set before publishing. Contact: `TBD`.

## 14. Current state: prototype versus target

| Control | Prototype | v10 target |
|---|---|---|
| Canonical encoding | Own `canon.py`, not RFC 8785 | RFC 8785 JCS in Rust |
| Tamper evidence | Hash chain with per-entry signatures | Merkle tree, signed checkpoints, global log |
| Signer isolation | Key mounted in the ledger container | Separate process and volume |
| Masking | Regex masks | Policy-driven salted commitments |
| Auth | Bearer tokens, no real login | Scoped, expiring, hashed tokens; approver keys |
| Approvals | `approved_by` is a name | Ed25519-signed approvals |
| Secrets in build | `COPY . .` may copy `secrets/` (no `.dockerignore` yet) | `.dockerignore` (now in `deploy/` and `prototype/`, tested in `tests/security/test_build_context_hygiene.py`), secret scanning in CI |
| Timestamps | Local clock | Labeled `claimed` |
| Dependency scan, encryption at rest, KMS/HSM | None | Dependency scan in CI; others later |

## 15. Security test checklist

Mapped to `TESTING.md` section 9. A capability stays `UNVERIFIED` until its tests pass.

- [ ] Arbitrary-root signing attempt is rejected.
- [ ] Gap, overlap, reordered sequence and fork attempts are rejected.
- [ ] Signer state corruption makes the signer fail closed.
- [ ] Edited, reordered, truncated and deleted events are caught by the verifier.
- [ ] A deleted run is caught by `abb verify-global`.
- [ ] Artifact swap is caught.
- [ ] Forged, expired and mismatched approvals fail.
- [ ] Out-of-mandate action is flagged.
- [ ] SSRF cases (private IPs, redirects, DNS rebinding) are blocked.
- [ ] Zip bomb, path traversal and nested archive receipts are rejected.
- [ ] Token scope tests: an adapter token cannot read other runs.
- [ ] Secrets never appear in logs, receipts or images.
- [ ] Container runs as non-root; signer volume is not mounted elsewhere.
- [ ] Restore from backup works for database, MinIO, signer state and keys.

## 16. Known limitations (state these plainly)

- Unobserved actions are invisible. Coverage labels say what was gated, observed or unknown.
- A compromised capture host can fabricate evidence before it is hashed.
- A valid hash does not prove a screenshot is genuine or a page truthful.
- One machine with all its backups rolled back is not detectable without an external anchor.
- Timestamps are claims unless trusted timestamp evidence is attached.
- A signed approval proves a key signed, not which human held it.
- The prompt guard and the anomaly auditor are not complete defenses.
- Availability and tenant isolation are out of scope for v10.
- **Dashboard read routes have no `Host` check.** `services/dashboard/server.py` checks the loopback `Host` header only on the run-console routes. `/api/receipts`, `/api/receipt`, `/api/verify`, `/api/alerts` and `/api/graph` do not, so a web page that rebinds a hostname to `127.0.0.1` could read receipt summaries and make the server run `abb verify`. Found in a static review on 2026-10-18, not exploited. Fix: refuse a non-loopback `Host` on every `/api/` route.
- **The graph database has no password.** FalkorDB (`deploy/docker-compose.yml`, profile `graph`) is reachable only on `127.0.0.1`; anyone with local access can read or change the graph. It is an index of receipts, so a changed graph cannot make a receipt valid or invalid. `services/graph/store.py` also names a database graph from the receipt's run id (receipt data is untrusted); restrict that id to a safe character set and length.
- **Temporary debug output in the run console (2026-10-18 copy).** `services/dashboard/runner.py` prints `APPROVAL DEBUG` lines with the exception and, for a failed signing command, its stderr and stdout, to the server output. That can include file paths and tool messages, which the run-console rules above say must not be logged. Remove it before sharing logs or publishing.
- **The Rust build is not run with `--locked`** in `deploy/signer.Dockerfile`, and two base images (`postgres`, `alpine`) are pinned by tag, not by digest.
- **Endpoint review** is not a security product: its events are simulated except those of the opt-in collector, its isolation is simulated, a score is a rule sum, and an alert is not proof of anything (`endpoint/README.md`).
- **Payments** use Stripe test mode only. A key without a test prefix is refused and any reply that does not say `livemode: false` is not trusted. Real money is out of scope and forbidden by the project rules.
