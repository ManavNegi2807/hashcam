# Running the demo

**Status:** `TESTED` on Windows with PostgreSQL 18.4 and Rust 1.90, on
2026-10-17. It has not been run on Linux or macOS, and it has never been run
through Docker Compose (no daemon was available), so "one command from a fresh
checkout" is **not** claimed yet.

The demo is the honest version of `PRODUCT_REQUIREMENTS.md` section 9: it runs
the real signer, the real API, the real policy gateway and the real offline
verifier, and it says out loud which beats are not built.

## What you need

| Thing | Why | Check |
|---|---|---|
| Rust (stable) | builds `abb` and `abb-signer` | `cargo --version` |
| Python 3.11+ | the service and the demo script | `python --version` |
| A PostgreSQL you can create databases on | the ledger | `psql -c "select 1"` |

The demo creates its own throwaway database and its own keys, and deletes the
work directory when it finishes. It never touches an existing schema.

## Build and run

```bash
pip install -r requirements.txt -r requirements-dev.txt
cargo build -p abb-cli -p abb-signer --manifest-path core/Cargo.toml
python tools/demo.py --dsn postgresql://USER@127.0.0.1:5432/postgres
```

On Windows, if the checkout sits deep in the filesystem, build with a short
target directory — `link.exe` fails past 260 characters:

```bash
CARGO_TARGET_DIR=C:/abb-target cargo build -p abb-cli -p abb-signer --manifest-path core/Cargo.toml
```

Add `--keep` to keep the work directory (receipts, keys, signer state) for
poking at afterwards. The script exits non-zero if any beat does not behave as
stated, so it is also a smoke test.

## What you will see

Each beat prints what it did and what the offline verifier said, and the script
exits non-zero if any beat does not behave as stated.

| Beat | What happens | What the verifier says |
|---|---|---|
| 1. run | A replay run through the real policy gateway. One action is denied by policy (`evil.example`) | |
| 2. receipt | The run is finalized, signed and exported | `VALID` |
| 2b. witnesses and anchor | Witnesses sign the global checkpoint and it is published to an append-only anchor file | on one machine: `PARTIAL`, witnesses and anchor `NOT_INDEPENDENT`. With `--simulate-second-device`: the quorum passes, **labelled as a simulation** |
| 3a. edit one event inside the receipt | One character of an event is changed | `INVALID`, naming the event |
| 3. edit one event in the database | A superuser rewrites a row and the run is exported again | `INVALID` |
| 3b. swap an artifact | A captured page is replaced inside the receipt | `INVALID`, naming the artifact by digest |
| 5. a signed approval | A gated action (bank details) waits. A person signs with `abb approve` using a key the API never sees; the gate opens | `VALID`; then one character of the signature is flipped: `INVALID` |
| 6. a signed mandate | The issuer signs "navigation only". The gateway blocks the form submission as `MANDATE_VIOLATION` | `VALID`, `mandate_compliance = PASS` |
| 7. a hidden value | A fake card number is typed into a form. It is committed to, not stored; it appears nowhere in the receipt. Its salt and value are then shredded | `VALID` both times |
| 3c. a rollback | The database is restored to an earlier, internally consistent state | the local check cannot see it; the anchor does |
| 4. delete a whole run | A run and its global-log row are removed | `abb verify-global` reports the gap |

Receipts from the demo now also carry the advisory channels: `semantic_assessment`
and `prompt_security_assessment` are `PASS` with their limits written next to the
result, and `behavior_anomaly_assessment` is `UNKNOWN` unless the anomaly rules ran.

## Other things to run

```bash
# A real Chromium, every request through the gateway, coverage measured first:
python tools/demo_playwright.py --dsn postgresql://USER@127.0.0.1:5432/postgres
python tools/demo_playwright.py --dsn ... --leaky      # an adapter with a hole: declares STEP_OBSERVED

# The audit dashboard over a folder of receipts (127.0.0.1 only, read-only):
python tools/ui_server.py --receipts <dir> --keys <key_manifest.json>

# How a rerun differs from an earlier run (advisory):
python tools/replay_drift.py first.abbreceipt second.abbreceipt
```

Playwright needs its browser once: `python -m playwright install chromium`.

## What the demo does not show, and why

| Missing | Because |
|---|---|
| An **independent** witness or anchor | Nothing here runs on a second device or a public repository. On one machine the verifier correctly says `NOT_INDEPENDENT`; the simulated mode only exercises the quorum rules |
| MinIO | No Docker daemon was available. Artifacts live in a local content-addressed folder behind the same interface |
| A TinyFish run from this project's own client | Needs your `TINYFISH_API_KEY`. Two live runs were made earlier through the session connector (`docs/TINYFISH_SPIKE.md`); the project client is tested only against a local fake. Try it: `python tools/demo_tinyfish.py --dsn ...` (dry run), then `--yes-spend` (about 8 cents) |
| Who held the approver key | A signature shows a key signed, not which person held it |
| A trained anomaly model | None exists. The anomaly channel is readable rules and a drift comparison |
| WebRTC and other non-HTTP traffic in the Playwright run | Not gated, and the declared coverage says so |

## Verifying a receipt by hand

The receipt is a portable file; verification needs no database and no network:

```bash
abb verify run.abbreceipt --keys key_manifest.json --profile LOCAL_ONLY
abb verify run.abbreceipt --json          # machine-readable, same answer
```

Exit codes: 0 `VALID`, 1 `INVALID`, 2 `INCOMPLETE`, 3 `PARTIAL`,
4 `UNSUPPORTED`, 65 a container it refused to read at all.

Without `--keys`, signatures are reported `UNKNOWN` and the overall result is
`INCOMPLETE` — never `VALID`. The key manifest is meant to reach you through a
channel independent of the receipt.

## The run console (a human gives the task)

`python tools/ui_server.py --receipts <dir> --enable-runs` adds a "Give the agent a task" form to
the dashboard. Off by default; without the flag the server stays read-only.

* A person types the task and picks a start site (only the sites in policy `tinyfish-demo`, today
  `example.com`). The page shows the worst-case cost; the run starts only after the person ticks
  the box and presses the button, and the server refuses a confirmed cost lower than its own.
* The run is `tools/demo_tinyfish.py --out <dir>`: same events, same signed receipt. When it
  finishes the page verifies the receipt with the offline verifier and shows it. The receipt has
  its own key manifest beside it (`<name>.keys.json`), made by the same machine, so it is not an
  independent channel.
* The TinyFish key stays in the environment of the server process (`TINYFISH_API_KEY`); it is never
  sent to the page, put on a command line or logged.
* Guards: a random token the page gets from the server, loopback `Host` only, same-origin only, one
  run at a time, 5-minute kill. `TESTED`: `tests/ui/test_run_console.py` (18 tests, three guard
  mutations caught). **Not tested with a real run through the page** until you do one.
* The agent runs on TinyFish's servers; this page does not show it live, only the log of the
  local script and then the receipt.

## Answers: Search, Research and Browse (TinyFish)

The `/run` page has five modes. Three call TinyFish with the key in `TINYFISH_API_KEY`:

| Mode | Calls | Status |
|---|---|---|
| Search | `GET https://api.search.tinyfish.ai` | The response shape was checked against a real answer (through the session connector). The project's own client has **not** yet been run live with your key for Search. `UNVERIFIED` live |
| Research | `POST /v1/automation/run-research-async`, then poll | Written from TinyFish's published reference only. Takes 5 to 20 minutes and must be switched on for the account. `UNVERIFIED` live |
| Browse | the TinyFish agent (`/v1/automation/run-async`) | `MEASURED` on real runs (cost = steps x $0.016). Some tasks sat at 0 steps until cancelled; the cause is not known |

Search and Research are read-only question answering. They are not the project's main point and cannot be gated: the provider's own answer is shown, and the receipt records only that it was received.

## The approval gate on a real website (measured by hand, 2026-10-18)

`tools/demo_realsite.py` (the "Real website" mode) drives a real Chromium at the real public test site
`httpbin.org/forms/post`. Policy `realsite-guarded` allows only that host and says: **reading is
free, submitting a form needs a person's signed approval first.** The bypass probes run before the
run, and `STEP_GATED` is declared only if they pass.

Two real runs, each with a real signature from `abb approve` and an offline `abb verify`:

| Approver says | What happened | Receipt |
|---|---|---|
| Granted | the form was submitted; httpbin.org echoed the message back | `VALID`, `STEP_GATED` |
| Denied | nothing was sent | `VALID`, `STEP_GATED` |

`TESTED` automatically (without the internet) in `tests/adapter/test_playwright_approval.py`: a local
site's own request log shows the POST arrives only when the approval grants it, and never on a
denial, silence or no approver. The silent path was not run against the real site.

What this does **not** show: the approval rule gates form *submissions*; other requests are
policy-checked but not individually approved. A signature shows a key signed, not which person held
it (the key is on the same machine). The message you type is sent to a public test service, but only
if you approve.
