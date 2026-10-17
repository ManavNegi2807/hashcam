# Agent Black Box Protocol (ABB-P)

**Version:** `abb/1` (draft 0.2)
**Status:** DRAFT 0.2. Not frozen. Per architecture v9 §7, this document must be frozen, with cross-language test vectors passing, before any production receipt is emitted.
**Source architecture:** `Agent_Black_Box_Final_Architecture_v9_ML_Integrated.md` (sections cited as "v9 §n")
**Claim status of everything below:** `SPECIFIED`. Nothing here is `IMPLEMENTED`, `TESTED` or `MEASURED` yet (v9 §22).

Where v9 leaves a choice open, this draft makes a choice and records it as a decision (`D-nn`, section 20). Those decisions need your confirmation.

**Extensions beyond v9 (from the architecture review, D-10 to D-19):** a global log of run roots, salted field commitments, a signer that recomputes the root itself, signed human approvals, an optional signed mandate, and explicit witness independence. They are marked `(ext)` and can be dropped without touching the v9 core, except D-10 and D-12, which change the checkpoint and signer flow.

---

## 1. Scope and conventions

- The protocol defines: canonical encoding, hashing, events, run states, Merkle tree, artifact manifest, checkpoints, signer and witness requests, anchors, assessment records, receipts, and the verifier procedure and outputs.
- It does **not** define the UI, Temporal workflows, database schema, or adapter internals. Those are in `DESIGN.md`.
- The words MUST, MUST NOT, SHOULD and MAY are used in the RFC 2119 sense.
- "Hex" means lowercase hexadecimal, no prefix, no separators.
- `0x00` style literals are single bytes. `||` means byte concatenation.
- "Claim" means a value that the protocol records but cannot prove (for example a local timestamp).

## 2. Identifiers

| Name | Format | Notes |
|---|---|---|
| `protocol_version` | string, exactly `"abb/1"` for this draft | Verifier MUST reject unknown values as `UNSUPPORTED` |
| `schema_version` | integer, `1` for this draft | Version of event and receipt field layouts |
| `run_id` | string, lowercase UUID | One run is one event stream |
| `stream_id` | string, equal to `run_id` for run streams | Reserved so other stream kinds can be added. `"global"` is the global log of run roots (section 8.5) |
| `event_id` | string, lowercase UUID | Unique across the database |
| `sequence` | integer `>= 0` | Per run, strictly increasing by 1, no gaps |
| `key_id` | string, `"ed25519:" || hex(SHA-256(public_key_bytes))` | Identifies a verification key |
| `idempotency_key` | string, 1 to 128 ASCII printable characters | Unique per `(run_id, idempotency_key)` |

## 3. Canonical encoding

### 3.1 Canonical JSON

- All hashed or signed JSON MUST be serialized with **RFC 8785 JSON Canonicalization Scheme (JCS)**, encoded as UTF-8.
- The repository MUST contain JCS conformance vectors (valid, invalid, edge) used by every implementation.
- The exact canonical byte sequence of each event is **stored** and is the source of truth. Implementations MUST NOT recover signed bytes by re-serializing a PostgreSQL `JSONB` value.

### 3.2 Number rules

- Protocol numbers MUST be integers in `[-(2^53 - 1), +(2^53 - 1)]`.
- Floats, `NaN`, `Infinity`, `-0`, exponent notation, and numbers with a fractional part MUST be rejected at ingestion and by the verifier.
- Values that need fractions (for example scores) MUST be encoded as integers with a fixed scale, for example `score_ppm` (parts per million), or as decimal strings when the scale is open.

### 3.3 Strings and structure

- Strings are preserved exactly as received. The protocol applies no Unicode normalization. Producers SHOULD emit NFC.
- Lone surrogates and invalid UTF-8 MUST be rejected.
- Duplicate object keys MUST be rejected.
- `null` is allowed only where a field says so. Optional fields are **omitted**, not set to `null`.
- Unknown fields: allowed inside `payload` and `provenance` objects. At the envelope level, an unknown field is accepted only if its name starts with `x_`; any other unknown envelope field makes the event invalid.
- Proposed limits (tune after benchmark): canonical event size at most 65,536 bytes; nesting depth at most 16; single string at most 16,384 bytes. Large content goes into an artifact, not into an event.

## 4. Hashing and domain separation

Hash function: SHA-256 (FIPS 180-4). All digests are 32 bytes, shown as 64 hex characters.

Domain tags are ASCII strings followed by one `0x00` byte. They are fixed for `abb/1`.

| Purpose | Tag bytes (ASCII, then `0x00`) | Input after the tag |
|---|---|---|
| Event leaf data | `ABB1-EVENT` | canonical event bytes (section 5) |
| Checkpoint signing | `ABB1-CHECKPOINT` | canonical checkpoint payload bytes (section 10) |
| Artifact manifest entry | `ABB1-MANIFEST` | canonical manifest entry bytes (section 9) |
| Witness signing | `ABB1-WITNESS` | canonical witness payload bytes (section 12) |
| Key transition record | `ABB1-KEYROTATE` | canonical transition payload bytes (section 10.5) |
| Global log leaf (ext, D-10) | `ABB1-RUNROOT` | canonical run-root record bytes (section 8.5) |
| Field commitment (ext, D-11) | `ABB1-FIELD` | `salt (16 bytes) || JCS(value)` (section 5.5) |
| Human approval (ext, D-16) | `ABB1-APPROVAL` | canonical approval statement bytes (section 5.6) |
| Mandate (ext, D-16) | `ABB1-MANDATE` | canonical mandate bytes (section 5.7) |

Merkle tree prefixes (`0x00` leaf, `0x01` node) are defined in section 8.

**Artifact digest exception (D-03).** The digest of an artifact is `SHA-256(raw artifact bytes)` with **no tag**, because v9 §11 makes the MinIO object key equal to that digest. Domain separation still protects artifacts, because the manifest entry that commits to the digest is tagged.

## 5. Event envelope

An event is a JSON object with these envelope fields. All are required unless marked optional.

| Field | Type | Rule |
|---|---|---|
| `protocol_version` | string | `"abb/1"` |
| `schema_version` | integer | `1` |
| `run_id` | string | section 2 |
| `event_id` | string | section 2 |
| `sequence` | integer | section 2 |
| `event_type` | string | one of section 5.2 |
| `created_at` | integer | Unix time in milliseconds. A **claim** (section 10.4) |
| `source` | string | `reported_by_adapter`, `observed_by_local_gateway` or `verified_by_black_box` |
| `provenance` | object | section 5.1 |
| `payload` | object | per event type (section 5.2) |
| `artifact_refs` | array of strings | optional. Artifact digests (hex) used by this event |
| `policy_ref` | object | optional. `{policy_id, policy_version}` |
| `commitments` | object | optional (ext, D-11). Salted commitments for payload fields that are not stored in clear (section 5.5) |
| `idempotency_key` | string | section 2 |

The **canonical event bytes** are `JCS(event)`. The Merkle leaf data is `"ABB1-EVENT" || 0x00 || canonical_event_bytes`.

### 5.1 Provenance object

| Field | Type | Meaning |
|---|---|---|
| `adapter_name` | string | `replay`, `playwright`, `tinyfish`, or another registered name |
| `adapter_version` | string | exact version |
| `execution_id` | string | adapter run identifier (may be provider-assigned) |
| `mode` | string | `REPLAY`, `LIVE_LOCAL` or `LIVE_EXTERNAL`. ReplayAdapter output MUST use `REPLAY` (v9 §6) |
| `observed_coverage` | string | `TASK_LEVEL`, `STEP_OBSERVED` or `STEP_GATED` |

`source` values keep provider claims apart from local facts (v9 §12):

- `reported_by_adapter`: the adapter or provider said so.
- `observed_by_local_gateway`: the local policy gateway saw it happen.
- `verified_by_black_box`: Black Box itself checked it (for example a digest it recomputed).

### 5.2 Event types

All 21 event types from v9 §7. `Emitted by` is a proposal.

| `event_type` | Required payload fields | Emitted by |
|---|---|---|
| `RUN_STARTED` | `task_digest`, `adapter`, `policy_version`, `requested_coverage`; optional `mandate_digest`, `mandate_issuer_key_id`, `mandate_signature` (section 5.7) | orchestrator |
| `COVERAGE_DECLARED` | `requested_coverage`, `declared_coverage`, `in_scope_actions[]`, `reason`; optional `evidence_ref` (digest of a capability-test report, section 7) | orchestrator |
| `ACTION_REQUESTED` | `action_id`, `action_type`, `target`, `params_digest`; optional `amount_minor_units` (integer) | adapter via gateway |
| `ACTION_AUTHORIZED` | `action_id`, `policy_id`, `policy_version`, `decision`, `reason_codes[]` | policy gateway |
| `ACTION_BLOCKED` | `action_id`, `policy_id`, `policy_version`, `reason_codes[]` | policy gateway |
| `ACTION_DISPATCHED` | `action_id` | gateway |
| `BROWSER_OBSERVATION` | `action_id`, `observation_kind`, `url`, `text_digest` | adapter or gateway |
| `API_CALL_OBSERVED` | `action_id`, `method`, `host`, `status_code`, `body_digest` | adapter or gateway |
| `ARTIFACT_CAPTURED` | `artifact_digest`, `media_type`, `size`, `capture_method`, `manifest_index` | artifact component |
| `POLICY_VIOLATION_DETECTED` | `action_id`, `policy_id`, `policy_version`, `reason_codes[]` | policy gateway |
| `ACTION_SUCCEEDED` | `action_id`, `evidence_event_ids[]` | gateway |
| `ACTION_FAILED` | `action_id`, `error_code`, `retryable` | gateway |
| `OUTCOME_UNKNOWN` | `action_id`, `reason` | orchestrator |
| `HUMAN_APPROVAL_REQUESTED` | `action_id`, `approval_id`, `summary_digest` | orchestrator |
| `HUMAN_APPROVAL_GRANTED` | `approval_id`, `action_id`, `approver_id`, `approver_key_id`, `expires_at`, `approval_signature` (section 5.6) | control plane, relaying the approver's signature |
| `HUMAN_APPROVAL_DENIED` | `approval_id`, `action_id`, `approver_id`, `approver_key_id`, `reason`, `approval_signature` (section 5.6) | control plane, relaying the approver's signature |
| `ML_ANALYSIS_COMPLETED` | `model_id`, `model_version`, `feature_schema_id`, `score_ppm`, `reason_codes[]` | anomaly auditor |
| `SEMANTIC_INVARIANT_CHECKED` | `invariant_id`, `invariant_version`, `result`, `evidence_event_ids[]` | semantic monitor |
| `SEMANTIC_VIOLATION_DETECTED` | `invariant_id`, `invariant_version`, `severity`, `evidence_event_ids[]`, `status` | semantic monitor |
| `PROMPT_SECURITY_ANALYSIS_COMPLETED` | `detector_id`, `detector_version`, `verdict`, `score_ppm`, `reason_codes[]`, `source_digest`, `classifier_available` | prompt guard |
| `RUN_FINISHED` | `final_state`, `event_count`, `outcome` | orchestrator |

Value sets:

- `decision`: `ALLOW`, `DENY`, `REQUIRE_APPROVAL`.
- `result` (semantic): `PASS`, `FAIL`, `UNKNOWN`. Missing evidence MUST be `UNKNOWN`, never `PASS` (v9 §15A).
- `verdict` (prompt guard): `ALLOW`, `FLAG_FOR_REVIEW`, `BLOCK_BY_POLICY`. It is a signal to the policy gateway, not a permission.
- `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `status` (semantic violation): `OPEN`, `ACKNOWLEDGED`, `ESCALATED`.
- Any `action_type` that can change real-world state MUST pass through `ACTION_REQUESTED` and then `ACTION_AUTHORIZED` or `ACTION_BLOCKED` before `ACTION_DISPATCHED` when coverage is `STEP_GATED`.

### 5.3 Sequence, idempotency, commit

- The ingestion service assigns `sequence`. Adapters propose events; they do not choose sequence numbers.
- A duplicate `(run_id, idempotency_key)` returns the already-committed event. It never creates a second event.
- An event is **committed** when its row, the stream head update, and the outbox entry are in one database transaction (v9 §11). Only committed events may be published over SSE, hashed into a checkpoint, or signed.
- After `RUN_FINISHED` no more events are accepted for that run.

### 5.4 Checkpoints are not events

`CHECKPOINT_CREATED` MUST NOT exist as an event, because a checkpoint root cannot include an event that contains that root (v9 §7). Checkpoints are protocol records stored beside the event stream (section 10).

### 5.5 Salted field commitments (ext, D-11)

Some payload fields (passwords typed into a form, card numbers, personal data) must not sit in the ledger in clear, and an append-only log cannot delete them later. So they are committed instead of stored.

- The ingestion service applies the policy's redaction rules **before** the event is canonicalized. A policy decision can still use the clear value earlier, at the gateway.
- For a committed field `f`: the payload MUST NOT contain `f`, and `commitments.f = SHA-256("ABB1-FIELD" || 0x00 || salt || JCS(value))`, where `salt` is 16 random bytes from a CSPRNG, one per field per event. Commitments are lowercase hex.
- The salt and the clear value are kept in a separate secret store (`field_disclosures`), never in the ledger. Deleting that row is **crypto-shredding**: the commitment stays valid in the Merkle tree but the value is gone for good.
- To disclose a field later, the receipt carries `disclosures[]`: `{event_id, field, salt_hex, value}`. The verifier recomputes the commitment and compares it with `commitments.f`.
- Undisclosed fields leave the leaf hash, inclusion proof and every signature valid. Only dimensions that need the hidden value report `UNKNOWN`.
- What stays visible even when a field is hidden: event type, sequence, timing claim, payload size class, and the other fields. Policy MUST NOT hide fields that a deterministic check needs to run offline.
- Low-entropy values (for example a 4-digit PIN) are safe only because of the 128-bit salt. Salts MUST NOT be reused or derived from the value.

### 5.6 Signed human approvals (ext, D-16)

A `HUMAN_APPROVAL_GRANTED` or `_DENIED` event is only as strong as the proof that a person made it. So the approver signs a statement with a key the control plane does not hold.

- Approval statement: `{ "approval_id", "run_id", "action_id", "summary_digest", "decision": "GRANTED" | "DENIED", "expires_at" }`.
- Signing bytes: `"ABB1-APPROVAL" || 0x00 || JCS(statement)`. Signature: pure Ed25519 by the approver's key. The approver signs on their own device (CLI, or a browser using WebCrypto). P-256 and WebAuthn are a later protocol version.
- The approver's `key_id` MUST appear in the key manifest with role `approver` (section 10.5).
- `summary_digest` is the digest of exactly what the human saw (action type, target, key parameters). It MUST equal the `summary_digest` in the matching `HUMAN_APPROVAL_REQUESTED`.
- An approval is valid for dispatch only if the signature verifies, `action_id` matches, and `ACTION_DISPATCHED` was created before `expires_at` (a timestamp claim, so labeled as such).
- A missing or invalid signature on an approval that policy required makes `policy_assessment` `FAIL`.

### 5.7 Signed mandate (ext, D-16)

A mandate is a signed statement of what the agent was allowed to do in this run. It is optional. When present, "the agent stayed inside what the human allowed" becomes a check the verifier can run.

Mandate fields: `mandate_id`, `issuer_key_id`, `subject` (agent or adapter name), `allowed_hosts[]` (exact host or `*.suffix`), `allowed_action_types[]`, `max_actions` (integer), optional `max_spend_minor_units` (integer) with `currency`, `not_before`, `not_after` (ms, claims).

- Signing bytes: `"ABB1-MANDATE" || 0x00 || JCS(mandate)`. `mandate_digest = SHA-256(signing_bytes)`.
- `RUN_STARTED` carries `mandate_digest`, `mandate_issuer_key_id` and `mandate_signature`. The full mandate document travels in `receipt.json` under `mandate`.
- The gateway SHOULD treat the mandate as a deterministic policy input and block out-of-mandate actions. The verifier checks it again afterwards (dimension `mandate_compliance`, section 16).
- A mandate is evidence of the instructions, not enforcement by itself.

## 6. Run states

States (v9 §5): `PENDING`, `POLICY_CHECKED`, `DISPATCHED`, `OBSERVING`, `ANALYZING`, `FINALIZING`, `CHECKPOINTED`, `EXPORTED`. Exception states: `FAILED`, `OUTCOME_UNKNOWN`, `CANCELLED`, `POLICY_BLOCKED`.

Legal transitions (proposed; v9 requires defining them all and rejecting the rest at the service and database boundary):

| From | To |
|---|---|
| `PENDING` | `POLICY_CHECKED`, `POLICY_BLOCKED`, `CANCELLED`, `FAILED` |
| `POLICY_CHECKED` | `DISPATCHED`, `POLICY_BLOCKED`, `CANCELLED`, `FAILED` |
| `DISPATCHED` | `OBSERVING`, `OUTCOME_UNKNOWN`, `CANCELLED`, `FAILED` |
| `OBSERVING` | `ANALYZING`, `OUTCOME_UNKNOWN`, `CANCELLED`, `FAILED` |
| `OUTCOME_UNKNOWN` | `OBSERVING` (after reconciliation), `FINALIZING`, `FAILED` |
| `ANALYZING` | `FINALIZING`, `FAILED` |
| `FINALIZING` | `CHECKPOINTED`, `FAILED` |
| `CHECKPOINTED` | `EXPORTED` |
| `FAILED`, `CANCELLED`, `POLICY_BLOCKED`, `EXPORTED` | none (terminal) |

Rules:

- A worker MUST NOT blindly retry an irreversible action after a crash. If a remote call may have succeeded, record `OUTCOME_UNKNOWN`, reconcile, then decide (v9 §5).
- Worker leases carry a monotonically increasing **fencing token**. The ingestion service rejects events from a lower token than the current one.
- Each state change is stored in `run_state_transitions` and is not an event, except where an event type above says otherwise.
- (ext, D-10) `CHECKPOINTED` becomes `EXPORTED` only after the run's final checkpoint has been appended to the global log and a global checkpoint covering it exists (section 8.5).

## 7. Coverage levels

| Level | Meaning | Safe claim (v9 §6) |
|---|---|---|
| `TASK_LEVEL` | Task and reported result are kept | Task-level reporting only |
| `STEP_OBSERVED` | Adapter supplies per-step observations, recorded with provenance | Observed steps were recorded; not every action is necessarily intercepted |
| `STEP_GATED` | Every in-scope action passes the policy gateway before dispatch, with an authorization or blocked record | Gated actions are policy-checked before execution, within the declared boundary |

Rules:

- `COVERAGE_DECLARED` MUST list `in_scope_actions[]`. Anything not listed is out of scope and is not covered.
- `declared_coverage` MUST NOT be higher than what the adapter can evidence. Playwright counts as `STEP_GATED` only if navigation, clicks, form submits, downloads and relevant network requests are all mediated by the gateway. Otherwise downgrade.
- TinyFish MUST NOT be labeled `STEP_GATED` unless every in-scope action is verifiably gated before dispatch (v9 §13).
- (ext, D-14) Any event stream with `mode = LIVE_EXTERNAL` is capped at `STEP_OBSERVED` unless `COVERAGE_DECLARED.evidence_ref` points to a recorded capability-test report showing pre-dispatch gating. Without it the verifier reports `observation_coverage = FAIL` for a declared `STEP_GATED`.
- (ext, D-14) For declared `STEP_GATED`, every `ACTION_DISPATCHED` MUST have an earlier `ACTION_AUTHORIZED` with the same `action_id` in the same run. The verifier checks this from the events; a dispatch without it makes `observation_coverage` `FAIL`.
- Missing evidence is `UNKNOWN` or `INCOMPLETE`. It is not proof that an action did not happen.
- ReplayAdapter events MUST carry `mode = REPLAY`.

## 8. Merkle tree

**Construction (D-01):** the tree hash is the **RFC 6962 §2.1 Merkle Tree Hash** applied to protocol-defined leaves. This is not a claim of Certificate Transparency compliance, because the leaf data is defined by this protocol (section 5). RFC 9162 may replace it in a later protocol version.

Let `D[0..n-1]` be the leaf data of events with sequence `0..n-1`.

- Leaf hash: `LH(d) = SHA-256(0x00 || d)`
- Node hash: `NH(l, r) = SHA-256(0x01 || l || r)`
- Empty tree (`n = 0`): `SHA-256("")` (the digest of zero bytes)
- One leaf (`n = 1`): `LH(D[0])`
- `n > 1`: let `k` be the largest power of two with `k < n`. Then `MTH(D[0..n-1]) = NH(MTH(D[0..k-1]), MTH(D[k..n-1]))`

**Inclusion proof** (RFC 6962 §2.1.1 audit path) is a JSON object: `{ "leaf_index": int, "tree_size": int, "path": [hex, ...] }`.

**Consistency proof** (RFC 6962 §2.1.2) is a JSON object: `{ "first_size": int, "second_size": int, "path": [hex, ...] }`.

Verifiers MUST reject: `leaf_index >= tree_size`, `first_size > second_size`, `first_size = 0` for non-empty proofs, wrong path length, non-hex or wrong-length hashes, and any proof with extra elements.

### 8.5 Global log of run roots (ext, D-10)

One tree per run cannot show that a whole run was deleted: if the run and its checkpoints vanish, nothing left refers to them. So all finalized runs are also appended to one **global log**.

- The global log is an ordinary stream with `stream_id = "global"`, built with section 8 exactly as for runs. There is one global log per deployment.
- Global leaf data: `"ABB1-RUNROOT" || 0x00 || JCS(record)`, where `record = { "run_id", "checkpoint_hash", "tree_size", "root_hash", "manifest_head", "finalized_at" }` taken from the run's **final** checkpoint. The Merkle leaf hash then adds the usual `0x00` prefix.
- A global checkpoint uses the section 10 layout with `stream_id = "global"`, `manifest_size = 0` and `manifest_head` of 64 zeros. `tree_size` is the number of finalized runs.
- The signer appends a run root only for a checkpoint that **it signed itself** (it checks its own state log). A run root cannot be injected by anyone else.
- Witnesses (section 12) and anchors (section 13) sign and publish **global** checkpoints. Run checkpoints are covered through the global tree, so no per-run witness traffic is needed.
- The receipt carries the run's global inclusion proof and the global checkpoint chain needed to reach an anchored or witnessed checkpoint (section 15).
- `abb verify-global` recomputes the global root from the list of run roots currently in the database and compares it with the latest witnessed or anchored global checkpoint. A deleted or altered run shows up as a different root, or as fewer runs than the anchored `tree_size`.
- Limit: an attacker who deletes a run **before** it is appended to the global log, or who rolls back everything including all anchors, is not detected.


## 9. Artifact manifest

The manifest commits to captured files and their order. It is separate from the event Merkle tree (v9 §15A.B). Checkpoints reference both.

Manifest entry fields:

| Field | Type | Rule |
|---|---|---|
| `index` | integer | 0, 1, 2, ... no gaps |
| `run_id` | string | |
| `event_id` | string | the `ARTIFACT_CAPTURED` event that announced it |
| `artifact_digest` | hex64 | `SHA-256(raw bytes)`, section 4 |
| `media_type` | string | |
| `size` | integer | bytes |
| `capture_method` | string | for example `playwright_screenshot`, `html_snapshot`, `download`, `response_body` |
| `captured_at` | integer | ms, a claim |
| `prev_manifest_hash` | hex64 | 64 zeros for index 0 |

- `manifest_entry_hash = SHA-256("ABB1-MANIFEST" || 0x00 || JCS(entry))`
- The **manifest head** is the hash of the last entry (64 zeros if the manifest is empty).
- The artifact component recomputes the digest after upload and again before export (v9 §11). A mismatch makes the artifact `CORRUPT` and the verifier reports `artifact_manifest_integrity = FAIL`.
- A matching digest proves the bytes equal what was committed. It does **not** prove the screenshot is genuine or the page was truthful (v9 §15A.B).

## 10. Checkpoints

A checkpoint commits to the event tree and the artifact manifest at one moment.

### 10.1 Checkpoint payload

| Field | Type | Rule |
|---|---|---|
| `protocol_version` | string | `"abb/1"` |
| `stream_id` | string | section 2 |
| `tree_size` | integer | number of committed events covered |
| `root_hash` | hex64 | `MTH` of those events |
| `manifest_size` | integer | entries in the manifest |
| `manifest_head` | hex64 | section 9 |
| `prev_checkpoint_hash` | hex64 | 64 zeros for the genesis checkpoint |
| `key_id` | string | signer key |
| `created_at` | integer | ms, a claim |

### 10.2 Signing

- `signing_bytes = "ABB1-CHECKPOINT" || 0x00 || JCS(payload)`
- Signature: pure **Ed25519** (RFC 8032), 64 bytes, shown as hex. Ed25519ph and other variants are not allowed.
- `checkpoint_hash = SHA-256(signing_bytes)`. The signature is not part of the hash, so a re-signed identical payload keeps the same `checkpoint_hash`.
- A stored checkpoint is `{ payload, signature }`.

### 10.3 Rules

- The genesis checkpoint has `prev_checkpoint_hash` of 64 zeros and `tree_size >= 1`.
- Each later checkpoint MUST extend the previous one: `tree_size` greater than before, a valid consistency proof from the previous `root_hash`, and `manifest_size` not smaller.
- Equal `tree_size` is allowed only as an idempotent return of the identical checkpoint (same `root_hash`, same `manifest_head`).
- Checkpoint publication (witnesses, anchors) is metadata outside the event stream (section 5.4).

### 10.4 Timestamps

`created_at` and `captured_at` are claims. They gain trust only from a separately verified trusted timestamp service (v9 §8). Git commit time is not one. Receipts MUST label timestamps `claimed` unless such evidence is attached.

### 10.5 Key distribution and rotation

- Verification keys come from a **key manifest**: a canonical JSON list of `{key_id, public_key_hex, role, failure_domain, valid_from, status}`, where `role` is `signer`, `witness`, `approver` or `mandate_issuer` published through a channel independent of the receipt (v9 §8).
- Rotation uses a transition record `{old_key_id, new_key_id, effective_checkpoint_hash, created_at}` signed by the **old** key over `"ABB1-KEYROTATE" || 0x00 || JCS(record)`, and also signed by the **new** key. The verifier accepts a key change only if the chain of transition records links to a key it already trusts.

## 11. Signer protocol

The signer is a separate process with its own key volume and no database credentials (v9 §4, §9).

### 11.1 Request (D-12)

The signer does **not** accept a root from the caller. It recomputes the root itself from the events, so a compromised caller cannot get an arbitrary root signed.

```json
{
  "stream_id": "<uuid or global>",
  "prev_checkpoint": { "payload": {}, "signature": "<hex128>" },
  "append": {
    "from_sequence": 0,
    "events": ["<base64 of canonical event bytes>"],
    "manifest_entries": ["<base64 of canonical manifest entry bytes>"]
  },
  "expected_root": "<hex64, optional cross-check>",
  "caller_attestation": "<Ed25519 signature by the ingestion service key over the request digest>"
}
```

For the `global` stream, `events` carries run-root records (section 8.5) and each must match a checkpoint in the signer's own state log.

**Append batch and `caller_attestation` (decision D-20, 2026-10-16; needs confirmation).** The open item is now implemented as:

- `append.events` and `append.manifest_entries` are arrays of **base64** of the canonical bytes. A request carrying digests instead of bytes is rejected with `BAD_APPEND_EVIDENCE`, because the signer cannot re-derive what it would be signing (D-12). A `leaf_hashes` field is named explicitly in that rejection.
- `caller_attestation = Ed25519_sign(ingestion_key, "ABB1-SIGNREQ" || 0x00 || JCS(request without caller_attestation))`.
- `ABB1-SIGNREQ` is **not** one of the nine domain tags of section 4 and does **not** bump `protocol_version`. The attestation is transport authentication between two local services: it is never stored, never enters a receipt, and the verifier never sees it. It still carries its own prefix so a signature over a request cannot be mistaken for a signature over a checkpoint.
- The signer's own state log is internal and needs no protocol tag: each entry is chained by `prev_entry_hash` and hashed with plain `SHA-256(JCS(entry))`.

The signer keeps, per stream, the Merkle **frontier** (the O(log n) hashes needed to extend the tree). It hashes the new leaves, extends the frontier and obtains the new `tree_size` and `root_hash` itself.

### 11.2 Validation (all MUST pass before signing)

1. The caller is authenticated (`caller_attestation` verifies against the configured ingestion key) and authorized for this stream.
2. `prev_checkpoint` equals the signer's **own** last accepted checkpoint for the stream (or a valid genesis for an unknown stream).
3. `append.from_sequence` equals the signer's current `tree_size` for the stream. No gap, no overlap.
4. Every event parses as strict canonical JSON (re-canonicalizing gives identical bytes), carries the right `protocol_version`, `run_id`, consecutive `sequence`, a known `event_type` and is within size limits. The first event of a new run stream is `RUN_STARTED`, and nothing follows `RUN_FINISHED`.
5. If `expected_root` is present, it equals the root the signer computed. If not, reject with `ROOT_MISMATCH`.
6. A batch that adds no events returns the identical stored checkpoint (idempotent). A request that would shrink the stream is rejected (`SIZE_REGRESSION`).
7. `manifest_entries` extend the manifest chain correctly (section 9), and the new `manifest_head` is computed by the signer.
8. No fork: the result does not conflict with anything the signer already signed.
9. The request is within the rate limit and is written to the audit log.

What this does and does not give: the signer proves the signed root really covers well-formed, correctly ordered events that extend its previous state. It cannot know the events are **true**. A compromised ingestion service can still submit false events. The defenses for that are the gateway (observation), the witnesses and the anchors, not the signer.

### 11.3 Persistence and failure

- The signer writes its new state **durably** before it returns a signature.
- The signer keeps a hash-chained append-only **state log**: `{stream_id, tree_size, root_hash, checkpoint_hash, key_id, transition_metadata}` per entry, each entry hashing the previous one.
- If its state is corrupt, the signer **fails closed** and refuses to sign until an explicit recovery ceremony. It never silently resets (v9 §9).

### 11.4 Error codes

`UNAUTHORIZED`, `UNKNOWN_STREAM`, `BAD_GENESIS`, `NOT_EXTENDING`, `SIZE_REGRESSION`, `FORK_DETECTED`, `BAD_APPEND_EVIDENCE`, `ROOT_MISMATCH`, `BAD_EVENT`, `GAP_OR_OVERLAP`, `RATE_LIMITED`, `STATE_CORRUPT`. (`BAD_PROOF` is verifier-only; the signer no longer receives proofs.)

## 12. Witnesses and quorum

**Quorum definition (D-02):** `2-of-3` **independent witnesses, in addition to** the primary signer. The primary signer is not counted as a witness. The other reading in v9 §10 is not used.

- Each witness has its own key and its own anti-rollback state.
- A witness independently verifies that the checkpoint extends its last seen checkpoint, then signs. It does not cosign blindly.
- Witnesses sign **global** checkpoints (section 8.5), so `stream_id` in the witness payload is `"global"` unless a deployment chooses to witness a run stream directly.
- Witness payload: `{ "witness_id", "stream_id", "checkpoint_hash", "tree_size", "failure_domain", "created_at" }`. Signing bytes: `"ABB1-WITNESS" || 0x00 || JCS(payload)`.
- `failure_domain` is a label such as `host:laptop-a/admin:alice`. It is also recorded for the signer in the key manifest. (ext, D-15)
- Two witnesses count as **independent** only if their `failure_domain` values differ from each other and from the signer's. Otherwise `witness_quorum` is `NOT_INDEPENDENT`, never `PASS`.
- `witness_quorum = PASS` needs at least 2 valid signatures from distinct independent domains. `FAIL` means a witness signature is invalid or a required witness is missing. `NOT_APPLICABLE` means no witnesses are configured.
- In `LOCAL_ONLY` there is no external anti-rollback claim (v9 §10).

## 13. Anchors

An anchor publishes a checkpoint digest outside the system (public Git repository, another administrator's repository, or a verified transparency or timestamp service).

Anchor record: `{ "stream_id", "checkpoint_hash", "tree_size", "location", "published_at", "evidence" }`.

- Anchors are out-of-band metadata. They are not events (v9 §10).
- (ext, D-10, D-15) Anchors publish **global** checkpoint digests. The recommended minimum is an append-only file in a public Git repository, one line per global checkpoint: `tree_size`, `checkpoint_hash`, `published_at`. Anchor records carry `anchor_domain`; an anchor in the same administrator's repository as the signer is reported `NOT_INDEPENDENT`.
- A Git timestamp is not a trusted timestamp.
- The verifier reports `anchor_match = PASS` only if the published `checkpoint_hash` equals one in the receipt's checkpoint chain, and `FAIL` if the anchored size is larger than the receipt's log or the hash differs.

## 14. Assessment records

Five channels stay separate in the UI and in receipts (v9 §15A.D). Each is built only from the events above.

| Channel | Source events | Meaning |
|---|---|---|
| `POLICY_ASSESSMENT` | `ACTION_AUTHORIZED`, `ACTION_BLOCKED`, `POLICY_VIOLATION_DETECTED`, `HUMAN_APPROVAL_*` | Deterministic allow, deny, approval |
| `SEMANTIC_ASSESSMENT` | `SEMANTIC_INVARIANT_CHECKED`, `SEMANTIC_VIOLATION_DETECTED` | Invariants against task behavior |
| `PROMPT_SECURITY_ASSESSMENT` | `PROMPT_SECURITY_ANALYSIS_COMPLETED` | Suspicious untrusted input |
| `BEHAVIOR_ANOMALY_ASSESSMENT` | `ML_ANALYSIS_COMPLETED` | Unusual trajectory |
| `EVIDENCE_INTEGRITY` | none (computed by verifier) | Events, artifacts, checkpoints |

Rules:

- ML and prompt-guard outputs MUST NOT override a deterministic deny and MUST NOT authorize an action (v9 §14, §15).
- ML records carry only `model_id`, `model_version`, `feature_schema_id`, `score_ppm`, `reason_codes[]`. Executable model files MUST NOT be embedded in a receipt (v9 §15).
- "Policy violation" and "off-allowlist" MUST NOT be used as input features of the anomaly model (v9 §15, circularity).
- An anomaly is not proof of malice. A prompt-injection score is not proof an attack worked. A valid hash is not proof the content is true.

## 15. Receipt format

**Container (D-04):** a ZIP file `*.abbreceipt` containing `receipt.json` (JCS-canonical) and an optional `artifacts/` folder named by digest. Verifiers MUST bound decompressed size, reject path traversal (`..`, absolute paths), and reject nested archives.

`receipt.json` fields (v9 §16):

| Field | Required | Content |
|---|---|---|
| `protocol_version`, `schema_version` | yes | |
| `run` | yes | `run_id`, adapter identity and version, `declared_coverage`, `observed_coverage`, `profile` (`LOCAL_ONLY` or `CONNECTED_EVIDENCE`) |
| `events` | yes | Canonical events (or event hashes with a flag `events_redacted`), each with its inclusion proof |
| `checkpoints` | yes | The checkpoint chain from genesis, with consistency proofs between them |
| `artifacts` | if any | Artifact digests, provenance, manifest entries, manifest head proof |
| `policy` | yes | Policy version and deterministic decisions |
| `semantic` | if present | Invariant set version and results |
| `prompt_security` | if present | Detector and model version, verdicts, scores, reason codes, source digests |
| `anomaly` | if present | Model version and metadata |
| `global_log` | yes (ext, D-10) | The run's inclusion proof in the global log and the global checkpoint chain up to the latest one included |
| `mandate` | if present (ext, D-16) | The full mandate document |
| `disclosures` | if any (ext, D-11) | Opened field commitments: `{event_id, field, salt_hex, value}` |
| `witnesses` | if any | Witness signatures and declared independence |
| `anchors` | if any | Anchor records |
| `key_manifest_ref` | yes | How to obtain verification keys (section 10.5) |
| `timestamps` | yes | Label `claimed` or attach trusted-timestamp evidence |
| `export` | yes | Exporter name and version, export time (claim) |

**Implementation status (2026-10-16, Step 5).** `receipt.json` as built carries
`protocol_version`, `schema_version`, `run` (`run_id`, adapter name and version, declared
and observed coverage, profile, root hash), `events` (each with `canonical_b64` and an
`inclusion_proof` of `leaf_index`, `tree_size`, `path`), `checkpoints` (each with
`payload_b64`, `signature` and a `consistency_from_previous` proof), `policy`
(`policy_id`, `policy_version`, `body_digest`), `global_log` (`record_b64`, its
`inclusion_proof`, and the global checkpoint chain), `key_manifest_ref`, `timestamps`
(labelled `claimed`) and `export`. Added in Steps 6 and 8: `artifacts.manifest_entries` (base64 of each canonical entry; the
bytes themselves travel as `artifacts/<digest>` in the container), `witnesses` (each
`{statement_b64, signature}`) and `anchors` (each `{checkpoint_hash, tree_size, location,
anchor_domain, published_at}`). Still absent: `semantic`, `prompt_security`, `anomaly`
(Step 10), `mandate` and `disclosures` (Step 9). The container is a ZIP of stored entries; a verifier
refuses path traversal, nested archives and anything over its size or ratio limits before
reading a byte of content.

**Step 9 clarifications (no change to bytes, tags or layouts; they say how the existing rules are applied).**

* `mandate_compliance` is judged over **dispatched** actions (`ACTION_DISPATCHED` joined to `ACTION_REQUESTED`), not over proposals. A proposal the gateway blocked is the mandate working. A dispatch outside the mandate means the gateway did not enforce it, and fails.
* `max_actions` counts dispatches. The spend bound sums `amount_minor_units` of dispatched actions. A target that is not an `http` or `https` URL is outside any host list.
* `*.suffix` matches the bare suffix too, exactly as the gateway's `host_matches` does.
* An approval needs a signed statement in `receipt.json` under `approvals`: `{statement_b64, key_id, signature}`. A `HUMAN_APPROVAL_GRANTED` event with none fails `policy_assessment`: the control plane's word is not an approval.
* An action that had a `HUMAN_APPROVAL_REQUESTED` and was dispatched needs a verified grant earlier in the sequence, and the dispatch's `created_at` must not exceed the signed `expires_at` (both are time claims). A dispatch after a signed denial fails.
* After a grant the gateway records `ACTION_AUTHORIZED` with reason `APPROVAL_GRANTED`, so the `STEP_GATED` rule that every dispatch has an earlier authorization still holds.
* `disclosures` carries `{event_id, field, salt_hex, value}`. A wrong value or salt, a salt that is not 16 bytes, a salt reused across disclosures and a field never committed all fail `evidence_integrity`. A committed field that is not disclosed leaves every hash and signature valid and is noted as unknown content. No dimension turns `PASS` because of it (see Q17).

**Steps 7, 10 and 11 clarifications (no change to bytes, tags or layouts).**

* **Coverage in the header comes from the events (question Q18).** `run.declared_coverage` is the last `COVERAGE_DECLARED.declared_coverage`; `run.observed_coverage` is the lowest `provenance.observed_coverage` any event carries. The verifier requires the header to equal both and judges the *event-derived* values; a header that disagrees fails `observation_coverage`, and a run with no `COVERAGE_DECLARED` event is `UNKNOWN`. The header is not signed; the events are.
* **`evidence_ref` for the Playwright adapter** is the digest of its bypass self-test report. The report itself is not in the receipt, so a reader can see that a measurement was cited but cannot re-check it from the receipt alone (`UNVERIFIED`).
* **Semantic records:** `PASS` only if at least one invariant was checked and none failed or was unknown; a failure names the invariant and the event sequence range of its evidence; a missing or unobserved step is `UNKNOWN`. A malformed record fails the channel. These dimensions are informational and never change the overall result.
* **Prompt-security records** must carry `classifier_available`; a clean run is `PASS` with its limits stated; `FLAG_FOR_REVIEW` or `BLOCK_BY_POLICY` is an advisory `FAIL` that names the source digest and says it is not proof of an attack.
* **Behavior-anomaly records** (`ML_ANALYSIS_COMPLETED`) may carry only `model_id`, `model_version`, `feature_schema_id`, `score_ppm`, `reason_codes`, `score_kind`, `threshold_ppm`. Any other field, such as a model body, fails the channel. A score is a rule sum, not a probability.
* **Provider metering** (`API_CALL_OBSERVED`) may carry `provider_execution_id`, `usage` (integers as returned) and `usage_observed_at`. Steps an external provider reports are `BROWSER_OBSERVATION` with source `reported_by_adapter`.
* **Adapter-level blocks** (for example `SSRF_BLOCKED`, `BUDGET_RESERVE_REACHED`) are recorded as an ordinary `ACTION_REQUESTED` followed by `ACTION_BLOCKED` naming the policy in force.

**Decision D-21 (proposed, needs confirmation).** Section 12 says `NOT_APPLICABLE` means no
witnesses are configured, and section 16.1 makes `witness_quorum` and `anchor_match` required
under `CONNECTED_EVIDENCE`. Read together they would let a connected receipt with no witnesses
count as satisfied. This build reports such a receipt as `UNKNOWN` for both dimensions (so the
overall result is `INCOMPLETE`), on the principle that missing evidence is never a pass.
`LOCAL_ONLY` still reports `NOT_APPLICABLE`.

Redaction: when events are exported as hashes only, the verifier can check inclusion but cannot judge the content. The affected dimensions report `UNKNOWN` and, if the dimension is required, the overall result is `INCOMPLETE`, never `VALID`.

Field-level redaction (section 5.5) is different: the events are complete, and only dimensions that need an undisclosed field report `UNKNOWN`.

## 16. Verification procedure and output

The verifier runs these steps in order. It never stops at the first failure; it fills every dimension it can.

1. Check `protocol_version` and `schema_version`. Unknown critical values give overall `UNSUPPORTED`.
2. Parse safely: size limits, no duplicate keys, integer-only numbers, UTF-8 valid.
3. Recompute each event's canonical bytes, leaf hash, and check its inclusion proof against its checkpoint.
4. Check event `sequence` is continuous and `run_id` is constant.
5. Verify every checkpoint signature, the `prev_checkpoint_hash` chain, and each consistency proof.
   5a. (ext, D-10) Verify the run's inclusion in the global log and the global checkpoint chain.
   5b. (ext, D-11) Recompute each disclosed field commitment.
6. Recompute artifact digests (if artifact files are present) and the manifest chain; compare the manifest head with the checkpoint.
7. Check key validity through the key manifest and transition records.
8. Check witness signatures and the quorum definition (section 12).
9. Check anchors (section 13).
10. Evaluate coverage honesty: declared coverage against provenance and gateway evidence.
11. Collect assessment channels (section 14) from signed events only.
12. (ext, D-16) Verify approval signatures (section 5.6) and, if a mandate is present, its signature and compliance (section 5.7).

### 16.1 Dimensions

Each dimension is one of `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`. `witness_quorum` and `anchor_match` may also be `NOT_INDEPENDENT` (section 12, D-15).

The 14 dimensions from v9 §16: `evidence_integrity`, `checkpoint_signatures`, `consistency`, `artifact_availability`, `witness_quorum`, `anchor_match`, `observation_coverage`, `policy_assessment`, `semantic_assessment`, `prompt_security_assessment`, `behavior_anomaly_assessment`, `artifact_manifest_integrity`, `ml_assessment` (aggregate display only; the individual dimensions stay visible), `execution_outcome`.

Added by this protocol (ext): `global_log_inclusion` (D-10) and `mandate_compliance` (D-16, `NOT_APPLICABLE` when no mandate).

**Required dimensions per profile (D-19):**

| Dimension | `LOCAL_ONLY` | `CONNECTED_EVIDENCE` |
|---|---|---|
| `evidence_integrity`, `checkpoint_signatures`, `consistency`, `global_log_inclusion` | required | required |
| `observation_coverage`, `policy_assessment` | required | required |
| `artifact_manifest_integrity` | required if artifacts exist | required if artifacts exist |
| `mandate_compliance` | required if a mandate exists | required if a mandate exists |
| `witness_quorum`, `anchor_match` | optional | required |
| `artifact_availability` | optional | optional |
| `semantic_assessment`, `prompt_security_assessment`, `behavior_anomaly_assessment`, `ml_assessment`, `execution_outcome` | informational | informational |

Informational dimensions are always shown but never change the overall result by themselves, so a `FAIL` in them is a finding, not a broken receipt.

### 16.2 Overall result (v9 §16)

| Overall | Rule (first match wins) |
|---|---|
| `UNSUPPORTED` | Unknown protocol, schema, adapter evidence, or critical field |
| `INVALID` | A cryptographic, structural, or policy-integrity check fails: any required dimension is `FAIL` |
| `INCOMPLETE` | No required dimension is `FAIL`, but a **required** dimension is `UNKNOWN` because evidence or artifacts are missing |
| `PARTIAL` | All required dimensions are `PASS` or `NOT_APPLICABLE`, but an **optional** dimension is `UNKNOWN` or `NOT_INDEPENDENT` |
| `VALID` | All required dimensions pass and no optional dimension is `UNKNOWN`, `FAIL` or `NOT_INDEPENDENT` |

Short version (D-19): `INCOMPLETE` means something the profile **requires** is missing. `PARTIAL` means everything required is fine but something **optional** is missing. An optional dimension that is `FAIL` (for example a bad witness signature) also gives `INVALID`, because a present signature that does not verify is an integrity failure.

The precedence above is a proposal (D-05). A valid signature never means the task was safe, correct, authorized or actually executed as claimed. Those are separate dimensions (v9 §16).

## 17. Conformance and test vectors

The Rust core, the CLI and the WASM build MUST produce identical results on all vectors (v9 §8, §17, §20).

**Status (2026-10-15, Steps 1 and 2 of `IMPLEMENTATION_PLAN.md`).** The first five sets exist in `vectors/`: JCS (11 canonical + 15 rejection cases), hashing and domain tags (10 + 5), Merkle (12 roots, 30 inclusion, 27 consistency, 7 malformed), checkpoints (10), global log (14) — 141 cases. They pass in **both** implementations: the Python reference in `vectors/tools/` that generated them, and the Rust core in `core/`, via `abb vectors check` (141 passed, 0 failed). So cross-language agreement for **these sets** is `TESTED`. The WASM build does not exist, so no claim is made that the CLI and WASM agree. The remaining sets below are still to create.

Vectors to create:

- JCS: key order, Unicode escapes, number rejection, duplicate keys, lone surrogates.
- Hashing: each domain tag with a known input, leaf and node hashes.
- Merkle: sizes 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17; inclusion and consistency proofs for each; malformed proofs.
- Checkpoints: genesis, extension, equal size replay, regression, fork, wrong key, rotation.
- Manifest: valid chain, broken link, wrong digest.
- Receipts: valid, modified event, invalid signature, bad consistency proof, missing artifact, unknown version, truncated file, malformed input, redacted events.
- Verifier statuses: one receipt for each overall result, plus one for each cell of the required-dimension table that can change the result.
- Global log (D-10): runs 1 to 5 appended, deleted run detected by `abb verify-global`, altered run root, injected run root the signer never signed.
- Field commitments (D-11): correct disclosure, wrong salt, wrong value, reused salt, shredded salt with valid leaf.
- Signer (D-12): events with a gap, overlap, reordered sequence, bad `event_type`, event after `RUN_FINISHED`, wrong `expected_root`, bad caller attestation.
- Approvals and mandate (D-16): valid and invalid signatures, wrong `summary_digest`, expired approval, out-of-mandate host, over `max_actions`.
- Witnesses and anchors (D-15): two witnesses in one domain give `NOT_INDEPENDENT`, signer-domain collision, anchor mismatch.
- Coverage (D-14): `STEP_GATED` declared with a dispatch that has no earlier authorization; `LIVE_EXTERNAL` declared `STEP_GATED` without `evidence_ref`.

A capability stays `UNVERIFIED` until the matching vectors and tests pass (v9 §22).

### 17.1 Rejection reason codes (additive, no semantic change)

The rules in sections 3.2 and 3.3 already require these rejections. This table only
names the codes so vectors and implementations can agree on which rule fired; it adds
no new rule and does not change any hashed or signed byte.

| Code | Input that triggers it |
|---|---|
| `FLOAT_NOT_ALLOWED` | fractional or exponent number form, or a float value |
| `NAN_OR_INFINITY` | `NaN`, `Infinity`, `-Infinity` |
| `MINUS_ZERO` | the token `-0` |
| `LEADING_ZERO` | a number with a leading zero, for example `01` |
| `NUMBER_FORM_INVALID` | any other non-canonical number token, for example `+1` |
| `INT_OUT_OF_RANGE` | integer outside `[-(2^53-1), 2^53-1]` |
| `DUPLICATE_KEY` | repeated object key |
| `LONE_SURROGATE` | unpaired surrogate in a string or key |
| `INVALID_UTF8` | input bytes that are not valid UTF-8 |
| `STRING_TOO_LONG` | single string over 16,384 characters |
| `SIZE_EXCEEDED` | canonical form over 65,536 bytes |
| `DEPTH_EXCEEDED` | nesting deeper than 16 |
| `TRAILING_DATA` | more than one JSON document in the input |
| `SYNTAX_ERROR` | not JSON |

Merkle proof rejections use `LEAF_INDEX_OUT_OF_RANGE`, `PATH_TOO_SHORT`, `PATH_TOO_LONG`,
`NOT_HEX`, `FIRST_SIZE_ZERO`, `SIZE_REGRESSION` and `EMPTY_PROOF`. Checkpoint and global-log
rejections reuse the signer codes of section 11.4, plus `BAD_SIGNATURE`, `WRONG_KEY_ROLE`,
`GLOBAL_ROOT_MISMATCH` and `NOT_IN_SIGNER_STATE_LOG`.

## 18. Versioning and extension

- Any change to canonical bytes, tags, tree rules, or checkpoint layout requires a new `protocol_version`.
- New event types and new optional fields may be added in the same `protocol_version` only if old verifiers can ignore them without changing any hash input. A verifier MUST reject unknown **critical** fields, which are envelope fields that do not start with `x_`.

## 19. Security considerations

- The protocol proves that retained, signed history has not changed relative to trusted checkpoints. It does not prove an external browser action really happened, unless the observation itself is trustworthy or independently attested (v9 §1).
- A compromised capture process can fabricate evidence before it is hashed.
- One signer detects edits against its own state. It cannot defeat theft of its host and all backups. Independent witnesses and anchors reduce that risk (v9 §9).
- Rollback of one machine and all its backups together is not detectable without an external anchor.
- A host administrator can rewrite database rows. Checkpoints, witnesses and anchors are the defense, not database permissions (v9 §11).
- The signer recomputes roots from events (D-12). It still cannot tell whether the events are true; a compromised ingestion service can submit false but well-formed events.
- Deleting an entire run is detected through the global log only after the run has been appended and a global checkpoint has been witnessed or anchored (D-10).
- Salted commitments hide values but not their existence, timing or size (D-11).
- A signed approval proves a key signed a statement. It does not prove which human held the key (D-16).

## 20. Decisions and open items

| ID | Decision in this draft | Why | Needs |
|---|---|---|---|
| D-01 | RFC 6962 tree hash over ABB-defined leaves | v9 §8 asks to pick one exact construction. RFC 6962 is simple and well documented | Confirm |
| D-02 | Quorum is 2-of-3 independent witnesses **plus** the primary signer | v9 §10 says never mix readings | Confirm |
| D-03 | Artifact digest has no domain tag | MinIO key equals the digest (v9 §11) | Confirm |
| D-04 | Receipt is a ZIP with `receipt.json` | Simple, verifiable offline | Confirm |
| D-05 | Overall-result precedence in section 16.2 | v9 §16 lists the five results but not their order | Confirm |
| D-06 | Size and depth limits in section 3.3 | v9 §7 asks for maximum payload sizes | Benchmark and tune |
| D-07 | Run-state transition table in section 6 | v9 §5 asks to define all legal transitions | Review |
| D-10 | Global log of run roots; witnesses and anchors sign global checkpoints (ext) | A per-run tree cannot show a deleted run | Confirm |
| D-11 | Salted field commitments instead of clear sensitive fields (ext) | Redaction and deletion rights without breaking proofs | Confirm |
| D-12 | The signer recomputes the root from events and a stored frontier (changes v9 §9 `append_evidence`) | Removes the vague "authenticated append record" trust link | Confirm |
| D-13 | Build order uses a reduced stack for the hackathon (see `DESIGN.md`); the protocol is unchanged | Scope | Confirm |
| D-14 | `LIVE_EXTERNAL` is capped at `STEP_OBSERVED` without test evidence; dispatch needs earlier authorization for `STEP_GATED` | Honest coverage story | Confirm |
| D-15 | `failure_domain` labels; `NOT_INDEPENDENT` result; Git file as the minimum anchor (ext) | Same-machine witnesses are not independent | Confirm |
| D-16 | Signed approvals (`ABB1-APPROVAL`) and an optional signed mandate (`ABB1-MANDATE`) (ext) | Proves who allowed what | Confirm |
| D-17 | Prompt guard defaults to deterministic checks only; the classifier is off by default (`DESIGN.md`) | BSL 1.1 license risk | Confirm |
| D-18 | The anomaly auditor is a stretch goal and advisory (`DESIGN.md`) | No labeled data | Confirm |
| D-19 | Required and optional dimensions per profile; `INCOMPLETE` vs `PARTIAL` defined by them (section 16) | The two results overlapped | Confirm |

Open items: write the remaining test vectors (receipt, manifest, approval, mandate, commitment, signer batch); choose the approver client (CLI first); define the key-manifest publication channel; decide how redacted receipts mark individual events. ~~Define the exact byte layout of the signer `append` batch and the request digest used by `caller_attestation`~~ — proposed as **D-20** in section 11.1, awaiting confirmation. ~~Choose the Rust crates~~ — pinned in `core/Cargo.toml`.

### Example event (illustrative, not a test vector)

Hash and signature values are placeholders because no vectors have been generated yet.

```json
{
  "protocol_version": "abb/1",
  "schema_version": 1,
  "run_id": "00000000-0000-4000-8000-000000000001",
  "event_id": "00000000-0000-4000-8000-0000000000a1",
  "sequence": 3,
  "event_type": "ACTION_BLOCKED",
  "created_at": 1760000000000,
  "source": "observed_by_local_gateway",
  "provenance": {
    "adapter_name": "replay",
    "adapter_version": "0.1.0",
    "execution_id": "replay-1",
    "mode": "REPLAY",
    "observed_coverage": "STEP_GATED"
  },
  "payload": {
    "action_id": "act-2",
    "policy_id": "default",
    "policy_version": "1",
    "reason_codes": ["DOMAIN_NOT_ALLOWED"]
  },
  "policy_ref": { "policy_id": "default", "policy_version": "1" },
  "idempotency_key": "run1-act2-blocked"
}
```
