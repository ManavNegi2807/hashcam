# Agent Black Box: Architecture and Requirements

**One line:** AI web agents do the work, every step is recorded in a signed, hash-chained log anyone can verify, and the final payment is signed by a human, never by the agent.

Built for AzinHack (sponsors: TinyFish, Docker). Stack: Python, LangGraph, TinyFish, Streamlit, Docker.

---

## 1. Problem

- AI agents now act on live websites (search, forms, logins, checkouts), but nobody can prove what an agent actually did.
- Normal logs can be edited by whoever owns the server, so they are weak evidence in a dispute.
- Giving an agent the power to pay is risky: if the agent is hacked or tricked, money can move.

## 2. Solution

A wrapper around the agent that does three things:

1. **Runs** the task through TinyFish (the agent does the real web work).
2. **Records** every step in a tamper-evident log: URL, action, masked result, screenshot hash, hash chain, Ed25519 signature.
3. **Separates payment**: the agent only prepares a payment. A trusted confirmation screen, outside the agent, shows the details, and the **user signs the final payment** (testnet wallet).

Anyone can later verify the log with only the public key and the log file. A public anchor (latest hash published outside the system) stops the log owner from quietly rewriting history.

## 3. Architecture

```
┌──────────── UI (Streamlit) ────────────┐
│ task box · live timeline · verify      │
│ tamper button · payment confirm screen │
└──────┬─────────────────────────┬───────┘
       │ task                    │ confirm (separate service)
┌──────▼───────┐         ┌───────▼────────┐
│ Orchestrator │         │ Payment module │──► User wallet signs (testnet)
│ LangGraph+LLM│         └───────┬────────┘
└──────┬───────┘                 │ tx ID
┌──────▼───────┐  allow/block    │
│    Guard     │◄────────────┐   │
│ allowlist,   │             │   │
│ limit, mask  │             │   │
└──────┬───────┘             │   │
┌──────▼───────┐       ┌─────▼───▼──────┐       ┌─────────┐
│ run_step     │──────►│ Recorder+Ledger│──────►│ Anchor  │
│ wrapper      │ record│ hash·sign·save │       │gist/test│
└──────┬───────┘       └─────┬──────────┘       └─────────┘
┌──────▼───────┐       ┌─────▼──────────┐
│   TinyFish   │       │ Verifier (CLI  │
│ search/fetch │       │ + UI)          │
│ browser/agent│       └────────────────┘
└──────────────┘
```

### Trust boundary (most important design rule)

- The **signing key lives only in the Ledger service**. The agent container has no key and no direct internet access.
- The agent can reach the web **only through `run_step`**, so it cannot skip the recorder.
- The **payment confirmation screen is a separate service**, not drawn by the agent, so a compromised agent cannot show a fake recipient or amount.

## 4. Components

| Component | Responsibility |
|---|---|
| **UI (Streamlit)** | Take the task, show the live timeline with screenshots and hash badges, verify button, tamper demo buttons, payment confirmation |
| **Orchestrator** | Plans the steps (LangGraph + LLM) |
| **Guard** | Allowlist of sites, spending limit, masking, approval rules. Blocked attempts are logged too |
| **`run_step` wrapper** | The only path to TinyFish. Calls TinyFish, then records the result |
| **Recorder + Ledger** | Canonical JSON, SHA-256 hash chain, Ed25519 signature, SQLite for entries, screenshots stored by hash |
| **Anchor** | Publishes the latest hash to a public place (GitHub gist first, testnet as a stretch) |
| **Verifier** | Recomputes the chain, checks signatures and screenshot hashes, reports the first broken step |
| **Payment module** | Prepares the payment, shows the trusted confirmation, records the user's approval and transaction ID |

## 5. Flow

1. User gives a task, for example "find the cheapest Poco X7 Pro and prepare the order".
2. Orchestrator plans steps and calls `run_step` for each.
3. Guard checks the action (allowed site, within limit). Blocked actions are logged and skipped.
4. `run_step` calls TinyFish and returns the result.
5. Recorder writes the entry: details, screenshot hash, previous hash, new hash, signature.
6. Agent prepares the payment (recipient, amount, site). It does **not** send money.
7. Confirmation screen shows the details. The user reads them and signs with their wallet (testnet).
8. The transaction ID is added to the log. The latest hash is anchored publicly.
9. Anyone can run the verifier: green means intact, red points to the first tampered step.

## 6. Log entry format

```json
{
  "n": 3,
  "time": 1760000000.0,
  "url": "flipkart.com",
  "action": "read price",
  "result": "Rs 23999",
  "shot": "<sha256 of screenshot>",
  "prev": "<hash of entry 2>",
  "hash": "<sha256 of canonical JSON of this entry>",
  "sig": "<Ed25519 signature over hash>"
}
```

Payment entries also carry `approved_by` and `tx_id`. Card numbers, OTPs and passwords are masked (for example `****1234`) and never stored in full.

## 7. Requirements

### Functional

1. The user can submit a task.
2. The agent performs web work through TinyFish.
3. Every step records URL, action, masked result and screenshot hash.
4. The guard runs before every sensitive action, and blocked attempts are logged.
5. The agent prepares payments only. The user signs the final payment.
6. The log can be verified at any time, and the first broken step is shown.
7. A tamper demo exists: edit a line, delete a step, truncate the end.
8. The latest hash is anchored to a public place.
9. A run "receipt" file can be exported and verified offline.

### Security

1. The signing key is never in code or in the agent container (use environment variables or a secrets manager).
2. Card, OTP and password data are masked in logs.
3. Payments are allowed only to allowlisted sites and recipients.
4. The agent container's network is locked so all traffic goes through `run_step`.
5. Webpage text is treated as data, never as instructions.
6. Sensitive actions need explicit human approval and respect a spending limit.
7. Logs and screenshots are encrypted at rest (stretch goal).

### Non-functional

| Area | Requirement |
|---|---|
| Tamper-evidence | Any edit, delete or reorder is detected |
| Reliability | Log is append-only, each entry written atomically |
| Performance | Recording adds only milliseconds per step |
| Portability | `docker compose up` starts everything |
| Testability | Tamper tests run automatically with pytest |

### Constraints and assumptions

- Testnet only, no real money, no real card data.
- TinyFish API key is available.
- About 48 hours of build time.
- Confirm early what a TinyFish run returns (steps, URLs, screenshots). If per-step screenshots are missing, capture them from a browser session or log page text and URL instead.

### Out of scope (future work)

KMS or HSM key storage, multi-signature, independent witness servers, real payments, security audit.

## 8. Tech stack

| Need | Tool |
|---|---|
| Agent flow | LangGraph |
| Web actions | TinyFish (search, fetch, browser, agent, monitors) |
| Hashing | `hashlib` (SHA-256) |
| Signatures | `cryptography` (Ed25519) |
| Storage | SQLite, screenshots as files named by hash |
| UI | Streamlit |
| Public anchor | GitHub gist API, then `web3.py` on a testnet (stretch) |
| Packaging | Docker Compose |
| Tests | pytest |

## 9. Threat model (qualitative)

Risk scores come from a simple estimate (likelihood x impact, reduced by control strength). They are **estimates from assumed inputs, not measured probabilities**.

| Attack | Control | Residual |
|---|---|---|
| Edit a log line | Hash chain + signature | Very low |
| Delete a middle step | Hash chain | Very low |
| Truncate last steps | Public anchor (more anchors + timestamp lower it further) | Low |
| Rewrite whole log (key theft) | Key outside agent, anchor (KMS/HSM and multi-signature in production) | Low to medium |
| Recorder bypass | `run_step` wrapper, Docker network lock | Low to medium |
| Prompt injection | Allowlist, approval, spending limit, content isolation | **Highest remaining risk** |
| Private data leak | Masking, encryption, access control | Medium |
| Fake payment page or wrong recipient | Separate confirmation screen, recipient allowlist, user reads before signing | Low to medium |

Honest framing: the system is **tamper-evident, not hack-proof**. It detects changes and limits damage. It does not stop a hacked agent from taking wrong actions, and it does not prove a website told the truth.

## 10. Folder structure

```
blackbox/
  agent/       LangGraph graph, run_step wrapper
  guard/       policy rules (allowlist, limits, masking)
  ledger/      record, sign, verify, anchor
  payment/     confirmation service, wallet signing (testnet)
  ui/          Streamlit app
  tests/       tamper tests (edit, delete, truncate)
  docker-compose.yml
  README.md
```

## 11. Build plan (2 days)

| When | Build |
|---|---|
| Day 1 morning | Run a TinyFish test and note what it returns. Define the entry format. Build hash chain, signing and verifier, with a tamper test. |
| Day 1 afternoon | Connect agent to recorder through `run_step`. Save screenshots by hash. One full demo task working. |
| Day 1 evening | Streamlit timeline with live verification badge. |
| Day 2 morning | Guard, payment confirmation screen, tamper demo buttons, anchor (gist). |
| Day 2 afternoon | Docker Compose with network lock, receipt export, README. |
| Day 2 evening | Demo script, slides, two rehearsals. |

## 12. Demo script (3 minutes)

1. Give a login-free task, such as finding the cheapest product on a shopping site.
2. Show the log growing live, with a screenshot and hash for each step.
3. Agent prepares the payment. The confirmation screen appears and the user signs (testnet).
4. Edit one line of the log by hand. Run the verifier: it flags the exact tampered step in red.
5. Show the public anchor to explain why even the log owner cannot quietly rewrite history.
6. Show a blocked action (over the limit, or a site not on the allowlist) appearing in the log.

## 13. Related work (say this before judges ask)

Similar tools exist, for example Aileron (hash-chained, signed audit log for agent tool calls), Gate OC Audit (Merkle-tree audit trail for OpenClaw agents) and AgentTrust Trace (signed evidence chain). Our focus is different: **web agents**, with screenshots hashed into the chain, a payment guard with human final signature, and a public anchor that works today.

## 14. Pitch

"AI only prepares the work. The human signs the payment. And every step is recorded in a log nobody can quietly change."
