# Agent Black Box: Detailed Design

Companion to `Agent_Black_Box_Architecture.md` (overview) and `REQUIREMENTS.md` (what must be built).
This file explains **how** each part is built.

---

## 1. Services and trust zones

| Service | Runs as | Holds | Can reach |
|---|---|---|---|
| **agent** | Docker container | LLM and TinyFish API keys, no signing key | Only the `ledger` service (no direct internet) |
| **ledger** | Docker container | Ed25519 signing key, SQLite, screenshot store | TinyFish API, anchor target |
| **payment** | Docker container | Nothing secret; draws confirmation screen | `ledger` (to record approval) |
| **ui** | Docker container | Nothing secret | `agent`, `ledger`, `payment` |

Rule: the agent never touches the web or the key directly. It asks the ledger service to run a step, and the ledger service calls TinyFish, records, and returns the result.

> If the agent must hold the TinyFish key for simplicity, keep the signing key in `ledger` and still route all calls through `run_step`. The signing key is the one that must stay out of the agent.

## 2. Module design

```
blackbox/
  agent/
    graph.py        LangGraph graph: plan -> act -> observe -> answer
    run_step.py     only function allowed to call the ledger API
  guard/
    policy.py       allowlist, limit, approval rules
    mask.py         card/OTP/password masking
  ledger/
    canon.py        canonical JSON
    chain.py        hash chain + signing
    store.py        SQLite + screenshot files
    verify.py       verifier (library + CLI)
    anchor.py       gist publisher (+ optional testnet)
    api.py          small HTTP API (FastAPI)
  payment/
    confirm.py      trusted confirmation page
    wallet.py       testnet transaction (signed by the user)
  ui/
    app.py          Streamlit app
  tests/
    test_chain.py   edit, delete, truncate, reorder
    test_guard.py   allowlist, limit, masking
```

### 2.1 `run_step` (the single gateway)

```python
def run_step(url, action, params=None):
    decision = guard.check(url, action, params)      # allow / block / need_approval
    if decision == "block":
        ledger.record(url, action, "BLOCKED: " + reason)
        return Blocked(reason)
    if decision == "need_approval" and not approvals.get(...):
        ledger.record(url, action, "DENIED or PENDING")
        return NeedsApproval()
    result, screenshot = tinyfish.run(url, action, params)   # real web work
    ledger.record(url, action, mask(result), screenshot)
    return result
```

A test scans the code and fails if anything outside `run_step` imports the TinyFish client.

### 2.2 Ledger entry and signing

```python
body  = {"n", "time", "url", "action", "result", "shot", "prev"}   # masked data only
hash  = sha256(canonical_json(body))
sig   = ed25519_sign(private_key, hash)
entry = {**body, "hash": hash, "sig": sig}
```

- `canonical_json` = sorted keys, no spaces, UTF-8.
- `prev` for entry 0 is 64 zeros.
- Screenshot bytes are stored as `shots/<sha256>.png`. Only the hash goes in the entry.

### 2.3 Verifier

```
for each entry in order:
    check prev == previous hash
    check sha256(canonical(body)) == hash
    check ed25519_verify(public_key, hash, sig)
    check shots/<shot>.png exists and sha256(file) == shot   (if file present)
compare final hash and count with the latest anchor
return OK, or "TAMPERED at step n" / "BAD SIGNATURE at step n" / "ANCHOR MISMATCH"
```

### 2.4 Guard policy

```yaml
allowed_sites: [test-shop.local]
sensitive_actions: [pay, submit_form, login]
limit_per_task_inr: 500
require_approval: [pay]
mask: [card, otp, password, cvv]
```

Decisions: `allow`, `block` (site or limit), `need_approval`. Every non-allow decision is logged.

### 2.5 Payment module

1. Agent calls `prepare_payment(recipient, amount, site)`. This only creates a **pending request** in the ledger.
2. The `payment` service reads the pending request **from the ledger** (not from the agent) and draws the confirmation page.
3. The user checks recipient, amount and site, then signs with their testnet wallet.
4. `payment` records `approved_by` and `tx_id` in the ledger.
5. If the user rejects or the limit is exceeded, the request is closed and logged.

The agent has no function that sends money and no access to any wallet key.

### 2.6 Anchor

- After every N steps and at run end, publish `{run_id, entry_count, tip_hash, time}` to a GitHub gist.
- Stretch: put `tip_hash` in a testnet transaction.
- Verifier fetches the latest anchor and compares.

## 3. Data design (SQLite)

```sql
CREATE TABLE runs (
  run_id     TEXT PRIMARY KEY,
  task       TEXT NOT NULL,
  started_at REAL NOT NULL,
  ended_at   REAL
);

CREATE TABLE entries (
  run_id  TEXT NOT NULL,
  n       INTEGER NOT NULL,
  time    REAL NOT NULL,
  url     TEXT NOT NULL,
  action  TEXT NOT NULL,
  result  TEXT NOT NULL,
  shot    TEXT NOT NULL,
  prev    TEXT NOT NULL,
  hash    TEXT NOT NULL,
  sig     TEXT NOT NULL,
  PRIMARY KEY (run_id, n)
);

CREATE TABLE payments (
  payment_id  TEXT PRIMARY KEY,
  run_id      TEXT NOT NULL,
  recipient   TEXT NOT NULL,
  amount_inr  REAL NOT NULL,
  site        TEXT NOT NULL,
  status      TEXT NOT NULL,        -- pending | approved | rejected | blocked
  approved_by TEXT,
  tx_id       TEXT
);

CREATE TABLE anchors (
  run_id       TEXT NOT NULL,
  entry_count  INTEGER NOT NULL,
  tip_hash     TEXT NOT NULL,
  location     TEXT NOT NULL,       -- gist URL or tx id
  anchored_at  REAL NOT NULL
);
```

Entries are insert-only. The application never runs UPDATE or DELETE on `entries` (the tamper buttons work on a **copy** used for the demo).

## 4. Internal API (ledger service)

| Method and path | Purpose |
|---|---|
| `POST /runs` | Start a run, returns `run_id` |
| `POST /runs/{id}/steps` | Run a step through TinyFish and record it |
| `GET /runs/{id}/entries` | List entries (for UI timeline) |
| `GET /runs/{id}/verify` | Run the verifier, return status and first broken step |
| `POST /runs/{id}/anchor` | Publish the current tip |
| `GET /runs/{id}/receipt` | Download the offline-verifiable receipt |
| `POST /payments` | Create a pending payment (from agent) |
| `POST /payments/{id}/approve` | Record user approval and `tx_id` (from payment service only) |

## 5. Sequence: task with a payment

```
User        UI        Agent       run_step     Guard     Ledger    TinyFish    Payment
 | task      |          |            |           |         |          |           |
 |---------->|--------->|            |           |         |          |           |
 |           |          | search     |           |         |          |           |
 |           |          |----------->| check     |         |          |           |
 |           |          |            |---------->|         |          |           |
 |           |          |            |<-allow----|         |          |           |
 |           |          |            |------------------- run -------->|           |
 |           |          |            |<----------------- result -------|           |
 |           |          |            |-- record(step) --->|           |           |
 |           |          | prepare    |           |         |          |           |
 |           |          |----------->| (pending payment)->|           |           |
 |           |          |            |           |         |   read pending         |
 |           |          |            |           |         |<-----------------------|
 |<------------- confirm screen (recipient, amount, site) --------------------------|
 | approve + wallet sign                                   |          |           |
 |--------------------------------------------------------------------------------->|
 |           |          |            |           |         |<-- approved, tx_id ----|
 |           |          |            |-- record(payment) ->|          |           |
 |           |<------------------ timeline + verify (green) |          |           |
```

## 6. UI design

### Main screen

```
┌───────────────────────────────────────────────────────────┐
│ Agent Black Box                      [ VERIFIED ✓  green ] │
├───────────────────────────────────────────────────────────┤
│ Task: [ find cheapest Poco X7 Pro, prepare order      ] [Run] [Stop] │
├───────────────────────────────────────────────────────────┤
│ #0  google.com     search        hash a1f3…   [screenshot] │
│ #1  test-shop      open page     hash 9c20…   [screenshot] │
│ #2  test-shop      read price    hash 4be7…   [screenshot] │
│ #3  test-shop      pay Rs 5000   BLOCKED (limit)           │
├───────────────────────────────────────────────────────────┤
│ [Verify]  [Tamper: edit]  [Tamper: delete]  [Tamper: cut]  │
│ [Export receipt]   Anchor: gist link                       │
└───────────────────────────────────────────────────────────┘
```

### Payment confirmation screen (separate service)

```
┌──────────────────────────────────────┐
│ Confirm payment (testnet)            │
│ Recipient : Test Shop (allowlisted)  │
│ Amount    : Rs 499                   │
│ Site      : test-shop.local          │
│ [ Reject ]            [ Sign & Pay ] │
└──────────────────────────────────────┘
```

Colors: green = verified, red = tampered, amber = blocked or pending. Use text labels as well as color.

## 7. Error handling

| Situation | Behavior |
|---|---|
| TinyFish call fails or times out | Log `ERROR: reason` as a step, retry once, then stop the run |
| Ledger write fails | Stop the run; never continue without recording |
| Verifier finds a break | Show red banner, step number and reason |
| Anchor publish fails | Keep running, mark anchor as `pending`, retry later |
| User closes confirmation screen | Payment stays `pending`, never auto-approved |
| Process killed mid-run | On restart, resume from the last complete entry |

## 8. Configuration

Environment variables (never in code):

```
TINYFISH_API_KEY=
LLM_API_KEY=
SIGNING_KEY_PATH=/run/secrets/signing_key
GITHUB_TOKEN=           # for gist anchor
ALLOWED_SITES=test-shop.local
LIMIT_PER_TASK_INR=500
ANCHOR_EVERY_N_STEPS=5
```

## 9. Docker Compose layout

```yaml
services:
  agent:
    build: ./agent
    networks: [internal]          # no external network
  ledger:
    build: ./ledger
    networks: [internal, external]
    volumes: [ledger_data:/data]
    secrets: [signing_key]
  payment:
    build: ./payment
    networks: [internal]
  ui:
    build: ./ui
    ports: ["8501:8501"]
    networks: [internal]
networks:
  internal: { internal: true }
  external: {}
```

The `internal` network blocks outside access, so the agent can only talk to the ledger.

## 10. Test plan

| Test | Expectation |
|---|---|
| Untouched log | Verifier returns OK |
| Edit one field of entry k | "TAMPERED at step k" |
| Delete entry k | Break at step k+1 |
| Reorder two entries | Break reported at the first out-of-order entry |
| Truncate last m entries | "ANCHOR MISMATCH" |
| Wrong public key | "BAD SIGNATURE" |
| Replace a screenshot file | Screenshot hash mismatch |
| Site not on allowlist | `BLOCKED` entry |
| Amount above limit | `BLOCKED` entry |
| Card number in a result | Masked in the log |
| Code scan | Nothing outside `run_step` imports the TinyFish client |
| Agent attempts a payment call | No such function exists; request stays pending |

## 11. Design decisions and why

| Decision | Reason |
|---|---|
| Hash chain plus signatures | Edit and delete are detected, and the author is proven |
| Public anchor | Detects truncation and full rewrites by the log owner |
| Single gateway `run_step` | The agent cannot skip recording |
| Signing key only in `ledger` | A hacked agent cannot forge the log |
| Separate confirmation service | A hacked agent cannot show a fake recipient or amount |
| User signs the final payment | The agent cannot move money even if compromised |
| Testnet only | Mistakes cost nothing |
| SQLite and files | Zero setup, fits in Docker, easy to demo |

## 11a. Extra controls (Could have, build after core)

| Control | Where in code | How |
|---|---|---|
| **Encrypt logs and screenshots at rest** (SR-05) | `ledger/store.py` | Encrypt each screenshot file and the SQLite file with `cryptography` Fernet. Key comes from the secrets path, never from code. |
| **Log access control** (SR-06) | `ledger/api.py` | Every endpoint checks an API token from the `Authorization` header. Read tokens can list and verify. Only the payment service token can call `POST /payments/{id}/approve`. |
| **Pinned and scanned dependencies** (SR-07) | `requirements.txt`, CI | Pin every package with `==`. Run `pip-audit` in the test step. |
| **Second check that action matches goal** (SR-08) | `agent/graph.py` | Before `prepare_payment`, a separate rule check (or a second LLM call with no web text) confirms recipient, amount and site match the user's original task. Mismatch means block and log. |
| **Anchor every N steps** (FR-61) | `ledger/anchor.py` | Already in 2.6. Config: `ANCHOR_EVERY_N_STEPS=5`. |

Build order: anchor and second check come with Step 2. Encryption, access control and pinning come after the demo works.

## 11b. More security ideas

### Must (Step 2)

| # | Idea | Where | How |
|---|---|---|---|
| M1 | **Tool allowlist** | `agent/graph.py` | Agent gets only `search`, `open_page`, `read_price`, `prepare_payment`. No shell, file or raw network function exists. |
| M2 | **Step limit** | `agent/run_step.py` | Max 20 steps per task. Stop and log `STEP LIMIT` if exceeded. |
| M3 | **Recipient allowlist** | `guard/policy.py` | `prepare_payment` only accepts recipients on the allowlist. New recipient needs separate approval. |

### Should (end of Step 2)

| # | Idea | Where | How |
|---|---|---|---|
| S1 | **Cooling period** | `payment/payment.py` | Payment waits 30 seconds after approval. User can cancel in that window. Cancel is logged. |
| S2 | **Amount double check** | `payment/payment.py` | Amount in the prepare step and on the confirmation screen come from the ledger row. Mismatch blocks the payment. |
| S3 | **Output check** | `agent/run_step.py` | Results must match a simple schema (for example, price is a number). Anything else is logged as `INVALID OUTPUT` and not passed to the agent. |
| S4 | **Domain pin** | `guard/policy.py` | Payment page must stay on the same domain. A redirect to another domain blocks the step. |

### Could (after the demo)

| # | Idea | Where | How |
|---|---|---|---|
| C1 | **Merkle tree** | `ledger/chain.py` | One root hash for all entries. Single entry can be proven without downloading the full log. |
| C2 | **Witness copy** | `ledger/anchor.py` | Each anchor saved in two places (gist and a local file). Verifier checks both. |
| C3 | **Receipt export** | `ledger/api.py` | One file with the full run that verifies offline (FR-24). |
| C4 | **Tamper alert** | `ledger/api.py` | Failed verify also writes a log entry and shows a red banner. |
| C5 | **Read-only verify mode** | `ledger/verify.py` | Anyone can run the verifier with only the log and public key. No write access. |
| C6 | **Blocked actions highlight** | `ui/index.html` | Blocked steps show in a different colour (FR-73). |
| C7 | **Short hash display** | `ui/index.html` | Each step shows the first 8 characters of its hash so judges can see the chain. |
| C8 | **TESTNET label** | `ui/index.html` | Confirmation screen shows a large "TESTNET" label. |

### Future work (put in README, do not build)

- **Trusted timestamp service:** anchor time comes from an outside authority.
- **Multi-signature:** payment needs two keys to sign.
- **Hardware key storage (KMS or HSM):** signing key never touches the server disk.

## 12. Known limitations (say them openly)

- Tamper-evident, **not** hack-proof.
- Prompt injection can still mislead the agent. It is recorded and limited, not eliminated.
- The log proves what the agent saw, not that a website was truthful.
- If the signing key is stolen and no anchor exists, the log can be forged.
- Blockchain payments cannot be reversed, which is why this prototype uses a testnet.
