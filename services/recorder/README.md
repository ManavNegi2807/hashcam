# services/recorder: the local service behind the browser extension

**Status:** `TESTED`: `tests/recorder/test_recorder_service.py` (11 tests: grant, deny, timeout,
out-of-passport, refused passkey, tripwire, drift, secret, kill switch, tampered receipt, API
guard), `tests/recorder/test_passkey.py` (9), `test_viewer_access.py` (11), `test_public_view.py` (5)
and the browser test `test_extension_e2e.py` (2).

| File | What it does |
|---|---|
| `session.py` | One recorded agent session. Every report from the extension goes through the existing policy gateway (`services/worker/gateway.py`) with policy `recorder` v1 and a signed passport (a mandate). Approvals are signed with `abb approve`; sealing uses the existing finalize, export and `abb verify`. |
| `server.py` | The HTTP API on `127.0.0.1`: pairing token, loopback `Host`, and no web `Origin`. |
| `passkey.py` | Checks the WebAuthn (passkey) answer before the approver key may be used. Trust on first use; the attestation is not examined. |
| `public.py` | What the **website's** read-only viewer may see of a session (below). Pure functions; `TESTED` in `tests/recorder/test_public_view.py` (5) and `test_viewer_access.py` (11). |

## The extension's browser checks (CORS)

Browsers normally let an extension call a host it has permission for without a CORS check, but some
do check, and then a flat refusal reads as a CORS error that cuts the extension off. So a preflight
(`OPTIONS`) from a `chrome-extension://` origin to a loopback `Host` gets the CORS headers back, and
the extension may read a refusal's text. A preflight carries no token and reveals nothing; every real
request still needs the pairing token, and a web page cannot send an extension origin. `TESTED` in
`tests/recorder/test_viewer_access.py`.

## Sensitive agents, and what the website sees

A session can be started with `sensitive: true` (the extension's "This agent handles sensitive data"
box). The extension and the local console are the person's own tools and still see everything. The
public site reads over the separate viewer key from a browser tab, so it is cut down on the server,
not just hidden on the page:

* **Always:** addresses lose their query string, fragment and `user:password` part (they carry
  tokens), and a step waiting for approval is described only as "a step is waiting" (its text names
  form fields).
* **For a sensitive session, also:** no task text, no passport sites, only the host of each address,
  no screenshots (the snapshot route answers 403), and no list of the sites the task names.

Screens that show a session (the site, the console, the extension) write each step as a plain
sentence and keep the raw record behind a closed "Technical details" opener; for a sensitive agent,
or a step that holds a secret, that opener says the record is hidden. See `ui/readable.js`. This is
display and transport hygiene, not a guarantee: the receipt itself is unchanged, and a page the agent
loads can still show what it likes.

Nothing here is new cryptography: hashing, Merkle trees and signatures are the Rust core's, and
the passkey check is the standard WebAuthn assertion check done with `cryptography`.
