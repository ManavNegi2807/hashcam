# services/recorder: the local service behind the browser extension

**Status:** `TESTED`: `tests/recorder/test_recorder_service.py` (11 tests: grant, deny, timeout,
out-of-passport, refused passkey, tripwire, drift, secret, kill switch, tampered receipt, API
guard), `tests/recorder/test_passkey.py` (9) and the browser test `test_extension_e2e.py` (1).

| File | What it does |
|---|---|
| `session.py` | One recorded agent session. Every report from the extension goes through the existing policy gateway (`services/worker/gateway.py`) with policy `recorder` v1 and a signed passport (a mandate). Approvals are signed with `abb approve`; sealing uses the existing finalize, export and `abb verify`. |
| `server.py` | The HTTP API on `127.0.0.1`: pairing token, loopback `Host`, and no web `Origin`. |
| `passkey.py` | Checks the WebAuthn (passkey) answer before the approver key may be used. Trust on first use; the attestation is not examined. |

Nothing here is new cryptography: hashing, Merkle trees and signatures are the Rust core's, and
the passkey check is the standard WebAuthn assertion check done with `cryptography`.
