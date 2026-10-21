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

# The same, with the run graph stored in FalkorDB (start it first, see below):
python tools/ui_server.py --receipts <dir> --falkordb redis://127.0.0.1:6390

# How a rerun differs from an earlier run (advisory):
python tools/replay_drift.py first.abbreceipt second.abbreceipt
```

Playwright needs its browser once: `python -m playwright install chromium`.

### The run graph (FalkorDB)

The audit view has a Graph section: one run drawn as nodes (`Run`, `Action`, `Policy`, `Approval`, `Mandate`, `Call`) and links (who requested what, which policy decided, which signed approval settled it, which provider call billed it). It is a picture of what is inside the receipt, never a verdict: the verdict stays the offline verifier's.

```bash
docker compose -f deploy/docker-compose.yml --profile graph up -d graph     # FalkorDB on 127.0.0.1:6390, no password
python tools/ui_server.py --receipts <dir> --falkordb redis://127.0.0.1:6390
```

Without `--falkordb`, or if FalkorDB is down, the page draws the same graph straight from the receipt and says so. Opening a run with FalkorDB connected saves its graph to the database (replacing the earlier one). To run the store tests: `ABB_TEST_FALKORDB=redis://127.0.0.1:6390 pytest tests/graph`. Not shown: any FalkorDB other than a loopback one, and graphs of more than one run at once.

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

## A witness on a second computer

A signer alone cannot show it was not rolled back. A **witness** keeps its own anti-rollback
state, rebuilds the tree and co-signs; it only counts as independent if its key lives on another
computer under another person's control. `tools/remote_witness.py` turns that into an exchange
of small files. Only the public checkpoint, the public run-root records and your public signer
key travel. The witness's private key never leaves its computer.

| Step | Where | Command |
|---|---|---|
| 1. make a witness key | the witness's computer (needs only the `abb` program and Python) | `python tools/remote_witness.py witness-init --domain host:NAME-laptop/admin:NAME` |
| 2. make a run and wait | your computer | `python tools/remote_witness.py host --dsn postgresql://... --work session` |
| 3. send `session/request/` to the witness | chat or USB | |
| 4. co-sign | the witness's computer | `python tools/remote_witness.py witness-sign --request request --reply reply` |
| 5. send `reply/reply.json` back | chat or USB | put it at `session/reply/reply.json` |
| 6. the receipt is built and verified | your computer | automatic; it prints what `abb verify` says |

Measured here (`tests/contract/test_remote_witness.py`, two folders on one machine): the exchange
works, the reply holds no secret, and a witness **refuses** a history that is not a continuation of
what it signed before. **Not measured: independence.** On one machine the two sides share a
computer, and the failure-domain label is a claim made in the key manifest, which you publish.
A single witness is not a quorum either: read the verdict the verifier gives. It has not been
tried with a second computer yet.

## Company payments with fake money

Pick **Pay bills** on the task page. Payments use an in-process **local mock gateway**. No Stripe,
API key, card details, external payment request, or real money is involved.

| Bill | Rule (policy `company-spend`) | What happens |
|---|---|---|
| up to 50.00 | pays on its own | simulated locally |
| over 50.00 up to 500.00 | needs a signed approval | an approval card shows **the amount and who is paid**; simulated only if you sign a grant |
| over 500.00 | refused outright | never dispatched, recorded as blocked (`OVER_AMOUNT_LIMIT`) |

Type bills like `Pay Acme Supplies 12.00 USD; Pay Cloud Hosting 180 USD; Pay Big Equipment 900 USD`
(up to 5, USD/EUR/GBP/INR), or leave the box empty to run one example in each tier.

The mock can simulate a successful payment, a decline, or an uncertain outcome. The default demo uses
success; pass `--scenario decline` or `--scenario unknown` to `tools/demo_pay.py` to exercise the
other paths. Idempotency keys prevent duplicate simulated charges within a client instance. Amounts
have a hard ceiling of 1,000.00. The gateway records outcomes, and the offline verifier checks the
receipt. Coverage remains `STEP_OBSERVED`, not `STEP_GATED`: there is no bypass test battery for
this adapter. These results demonstrate the policy and audit workflow only, not actual money movement.

## Endpoint review: events in, explained alerts out, everything sealed

This is the scenario from the deck (slide 7): an employee clicks a spoofed login link in chat. Pick
**Endpoint review** on the task page (or `python tools/demo_endpoint.py ...`). For each reported event:

1. the gateway records it and the collector's report is **sealed as an artifact** (by digest);
2. explainable **rules** score it (a rule sum, not a probability); a score of 300,000 or more is an
   alert, 600,000 or more is HIGH. An optional **Isolation Forest** gives a second, advisory opinion
   (lower "REVIEW" tier when only it flags something);
3. if the alert has a link, **TinyFish Search** (what web reports say) and **TinyFish Fetch** (what the
   page itself says, read by TinyFish's servers) are asked through the gateway. No key: the alert says
   "not asked", which is missing evidence, never "safe";
4. for a HIGH alert the analyst is asked to approve isolating the account. They sign with `abb approve`
   after reading who and why. **The isolation is simulated**: no real account exists or changes.

The **Alerts** section of the audit view shows each alert: how serious, each rule that fired in words,
the model's reasons, what TinyFish said (as the provider's claim), and whether an analyst signed.

Where events come from:

| Source | How | What it is |
|---|---|---|
| Built-in scenarios | type `phishing link in chat`, `big download at night`, `record queries`, or leave empty | **Simulated** events |
| A link you paste | type a sentence containing a web link | Scored, never opened from this computer; with a TinyFish key it is searched and fetched by TinyFish |
| The real collector | `python tools/endpoint_daemon.py --i-am-authorised --out events.jsonl --watch-downloads DIR --watch-processes --clicks-file links.txt`, then `python tools/demo_endpoint.py ... --events-file events.jsonl` | **Real events on this computer**, only what you point it at |

**What the real collector sees (and never does):** new finished files in ONE folder you name (name,
size, hour and where the browser says it came from; never contents, never the folder path); script
shells (`powershell.exe`, `cmd.exe`, ...) that start while it runs, with the program that started them
(names only, no command lines); and links you write to a file (it does **not** read browser history).
It needs `--i-am-authorised`, writes one readable JSON-lines file, and sends nothing anywhere. It is a
demo collector, not an endpoint security product.

**Measured** (`docs/MEASUREMENTS.md`, `python tools/measure_endpoint.py`): on **synthetic** labelled
events (made by the author of the rules, so optimistic, never real-world performance) the rules reach
about 0.73 precision and 0.8 recall with a 0.10 false-alarm rate, the Isolation Forest alone about 0.3
recall, and together they catch more of the hard phishing cases. Both miss most "hard" attacks built to
evade them. Scoring takes about 0.06 ms (rules) and 0.14 ms (model) per event. From an event being
recorded to its alert being written took about 3.3 to 4.4 s for the slowest alert in a full run on
this machine (each ledger event is committed over HTTP to PostgreSQL and the signer).

**Not measured / not built:** precision or recall on real traffic; TinyFish Fetch against the live
service (tested against a local fake that follows the documented API; run `python
tools/check_tinyfish_live.py --fetch` with your key); a real browser-history or chat integration; any
real account isolation; ETW or deep telemetry (roadmap).

## Artifacts in an S3-compatible object store

The deck says MinIO. MinIO's community edition was **archived upstream in April 2026** and no longer
publishes images (older releases carry a known high-severity flaw), so this project does not start new
deployments on it. `services/artifacts/s3_store.py` speaks the standard S3 API (AWS Signature V4, with the
standard library only) and works with any S3-compatible server, MinIO included. It was tested against
**SeaweedFS 4.48** (Apache-2.0): the signing matches AWS's published example, an existing object is never
overwritten, a swapped object is reported and never served, and a full endpoint run keeps its sealed
artifacts in the bucket. Set `ABB_S3_ENDPOINT`, `ABB_S3_ACCESS_KEY`, `ABB_S3_SECRET_KEY` (and optionally
`ABB_S3_BUCKET`) to use it; see `deploy/README.md` for the `storage` Docker profile.
