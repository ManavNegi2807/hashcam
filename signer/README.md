# signer — the separate signing service

**Status:** `TESTED`. 8 unit + 26 integration Rust tests, 13 HTTP contract tests
against the real binary, 4 fault-injection tests. The Compose wiring is
`IMPLEMENTED` but never run (no Docker daemon was available).
**Built in:** Step 4 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-SIG-01..13, R-GLB-02, R-CRY-03, R-OPS-03, decisions D-12 and
D-20.

It does one thing: given the previous checkpoint it issued and the canonical
bytes of the new events, it **recomputes the root itself** from a stored Merkle
frontier and signs a checkpoint over it. It never signs a root a caller supplies
(`D-12`).

## What a signature means, and what it does not

A checkpoint signature says: *these bytes are well formed, correctly ordered,
and they extend what this signer last signed.*

It does **not** say the events are true. A compromised ingestion service can
still submit false but well-formed events; the signer cannot tell. The defences
for that are the policy gateway (observation), the witnesses and the anchors —
not this process (`R-SIG-06`, `PROTOCOL.md` 11.2).

## API (`DATABASE_AND_API_CONTRACTS.md` B4)

| Route | Purpose |
|---|---|
| `POST /sign` | A signing request (`PROTOCOL.md` 11.1). Returns `{checkpoint, payload_b64, checkpoint_hash}` |
| `GET /state/{stream_id}` | The last checkpoint for a stream, for idempotent re-delivery |
| `GET /health` | Liveness, the key **id**, the protocol version. Never the key |

`payload_b64` carries the exact bytes the signature covers, so the caller stores
those rather than re-serializing the payload and hoping (`R-PRO-04`).

Error codes are those of `PROTOCOL.md` 11.4 with their own HTTP statuses:
`UNAUTHORIZED` 401, `UNKNOWN_STREAM` 404, `RATE_LIMITED` 429, `STATE_CORRUPT`
503, the extension conflicts (`NOT_EXTENDING`, `SIZE_REGRESSION`,
`FORK_DETECTED`, `ROOT_MISMATCH`, `GAP_OR_OVERLAP`) 409, and the malformed-input
codes (`BAD_GENESIS`, `BAD_EVENT`, `BAD_APPEND_EVIDENCE`) 422.

## Decision D-20 (needs your confirmation)

`PROTOCOL.md` 11.1 left the `caller_attestation` layout open. This build uses:

```
caller_attestation = Ed25519_sign(ingestion_key,
                                  "ABB1-SIGNREQ" || 0x00 || JCS(request without caller_attestation))
```

`ABB1-SIGNREQ` is deliberately **not** one of the nine protocol domain tags of
`PROTOCOL.md` section 4, and adding it does **not** bump `protocol_version`,
because the attestation is transport authentication between two local services:
it is never stored, never enters a receipt, and the offline verifier never sees
it. It still needs its own prefix so that a signature over a request can never
be mistaken for a signature over a checkpoint.

`abb attest --key <ingestion.key> --stdin` builds the body and signs it, so the
Python service never implements the canonical rules (`AGENTS.md` 3.10).

## Running it

```bash
abb keygen --out secrets/signer   --role signer     # the signing key
abb keygen --out secrets/ingest   --role approver   # the ingestion key pair

ABB_SIGNER_STATE_DIR=./signer-state \
ABB_SIGNER_KEY=./secrets/signer/signer.key \
ABB_SIGNER_INGESTION_PUBKEY="$(cat secrets/ingest/approver.pub)" \
ABB_SIGNER_ADDR=127.0.0.1:8081 \
ABB_SIGNER_RATE_LIMIT=50 \
abb-signer
```

Every variable is required except `ABB_SIGNER_ADDR` and
`ABB_SIGNER_RATE_LIMIT`. A missing value is an error, never a default: a signer
that invents its own key path is one nobody can reason about.

## State, durability and failing closed

`state.log` in the state directory holds one line per signed checkpoint. Each
line carries the hash of the line before it, and each entry records the stream,
the tree size, the root, the checkpoint hash, the frontier and the exact signed
payload bytes. A line is written and `fsync`ed **before** a signature is
returned (`R-SIG-09`).

On start-up the whole chain is verified. If any line has been edited, removed or
truncated, the signer **refuses to start** and says so; it never resets itself
(`R-SIG-10`). Recovery is an operator decision: inspect the log, restore the
last good copy from backup, and compare it against the latest witnessed or
anchored global checkpoint before accepting writes. There is no automatic path,
on purpose.

`state.lock` is an exclusive OS file lock held for the signer's lifetime. Two
signers on one state directory could each believe they hold the latest
checkpoint and sign conflicting histories, so the second one refuses to start.
Because the lock is held by the process, a crash releases it and the next start
works without a human.

`audit.log` records one line per request — stream, starting sequence, event
count, outcome — and never a key or an event payload (`R-SIG-11`).

## Isolation

No database credentials, no published port, its own read-only key volume. The
Compose rules are enforced by `tools/check_key_volume_isolation.py`, which runs
in CI and in `tests/security/test_compose_isolation.py`.

## Known gaps

* **Key rotation is not implemented.** `abb-checkpoint` has the transition
  record and verifies both signatures, but the signer never emits one and
  `transition_metadata` in the state log is always empty (`R-CRY-05` partial).
* **Offline key generation and backup are documented, not tested** (`R-SIG-13`).
  There is no restore test yet.
* **No witness or anchor publication.** The signer signs; distributing the
  global checkpoint is Step 8.
* A plain rollback to an older but internally consistent state log is **not**
  detectable here. That is what witnesses and anchors are for, and it is stated
  as a limit in `SECURITY.md` 16.
* `GET /health` answers even when the state is unusable only because the process
  refuses to start at all in that case; there is no degraded serving mode.
