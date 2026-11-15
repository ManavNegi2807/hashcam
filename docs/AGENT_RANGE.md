# HashCam Range

The Range is where a person points **their own AI agent** at **the real HashCam website** and gets a
scorecard from a record that checks out. This file says what exists today, what does not, and the design
for what comes next. **Everything under "Phase 2" and "Stage 2" is a design. None of it is built.**

## Status at a glance

| Piece | State |
|---|---|
| Catalog of 8 levels, task text, start panel (`site/range.html`) | **Built, tested** |
| Scorer (`site/range/score.js`), pass / fail / unknown per check, plain-language evidence | **Built, tested** |
| Grading a Gatekeeper Sandbox record (levels 1 to 6) | **Built, tested** |
| Grading an extension `.abbreceipt` (levels 7 and 8) | **Built.** Tested against the genuine, edited and key-less samples and with hand-made event lists. **Not yet tested with a receipt the extension recorded on this page** (needs the extension and a browser agent) |
| Shareable result link, SVG badge, copy-as-Markdown | **Built, tested** |
| Limits (`site/range/limits.js`): one "anonymous" plan, shown on the page | **Built. Shown, not enforced** |
| Sign-in, signed allowance, metering, abuse controls, kill switch | **Design only** (Phase 2) |
| Building an agent inside the site | **Design only** (Stage 2) |
| Prices, plans page, billing | **Does not exist and is not planned in this change** |

## What Phase 1 proves, and what it does not

A scorecard is only as good as the record under it. Phase 1 grades two kinds of record, and they prove
different things.

**Gatekeeper Sandbox record (levels 1 to 6).** The Range re-computes the whole hash chain in the browser
and checks every signature before it scores anything. A record that does not check out is *not scored*.
What it proves: the record was not edited after it was exported. What it does **not** prove:

* *Where it came from.* The sandbox signs with a key it creates in the page, and the key is inside the
  file. Anyone can make a record that checks out. The Range says so on every result.
* *Who pressed "Sign & Authorize".* The sandbox cannot tell an agent from a person. So a level that asks
  "did a person decide?" is graded **unknown**, never pass. A run can end *incomplete*, and that is the
  honest answer.

**Extension receipt (levels 7 and 8).** The Range runs the real verifier (WASM, with the plain-JavaScript
fallback that never says VALID) and scores only a receipt whose verdict is **VALID**. `INVALID`,
`INCOMPLETE` and unreadable receipts are not scored. The receipt is signed by a key the person controls,
and it lists what the agent asked for and what was allowed, held or blocked.

**The "run label".** The receipt does not carry the task text, so the label `RNG-XXXXXX` on the start panel
is a label the person writes into their task, not a proof that this receipt answers *that* task. The page
calls it a label for that reason. Phase 2 closes the gap (see the mandate below).

**Passing is not the same as safe.** A pass means the agent behaved on these eight tests, on this
page, in this run.

## Phase 1: how it works

```
 start a run            the agent works                 score my run
 ┌──────────┐          ┌────────────────┐            ┌───────────────────────────┐
 │ task text │────────▶│ real sandbox.html│──export──▶│ check record in the browser │
 │ run label │         │ or range.html    │           │ pass / fail / unknown       │
 │ passport  │         │ + the extension  │           │ share link · badge · .md    │
 └──────────┘          └────────────────┘            └───────────────────────────┘
```

Nothing is uploaded. Records are read and scored inside the page; the page makes no request while it does.
A shared result is only a summary (level, outcome, counts, date) in the URL fragment, which a browser does
not send to a server. The reader treats a fragment as untrusted: every field is checked, and it is shown
as text only.

Levels are data (`site/range/scenarios.js`, a `.js` file rather than `.json` so the pages still open from
`file://`). Adding a level means adding an entry there and a rule set in `score.js`, plus tests.

## Phase 2: a real allowance, enforced on a server

The Phase 1 limits are numbers on a page. Anyone can change a number on a page. Phase 2 makes a limit a
**fact in the receipt** that a server enforces. This section is a design.

### Sign-in: passkeys only

* WebAuthn passkeys. No passwords, no email-link fallback, nothing to phish or leak from a database.
* The server stores a credential id, a public key and a signature counter per credential. Nothing else
  about the person is needed to run the Range.
* A sign-in creates a short session (minutes) bound to the passkey and to the device. Sessions are never
  put in a URL.
* Recovery is a second passkey added in advance. No "forgot my password" path exists to attack.

### The signed allowance mandate

When a run starts, the server issues a **mandate**: a small signed statement of what this run may do.

```
mandate {
  run_id, run_label, plan, level,
  issued_at, expires_at,                 // minutes, not days
  allowed_hosts: ["hashcam.vercel.app"], // the passport
  max_steps, max_minutes,
  task_sha256                            // hash of the exact task text
}
signature = Ed25519(server_key, canonical(mandate))
```

* The extension reads the mandate and **records it as the first event of the receipt**
  (`RUN_STARTED` carries the mandate and its signature). From then on the receipt can show the run was
  authorised for *this* task (via `task_sha256`), on *these* hosts, until *this* time. That removes the
  "run label is only a label" gap above.
* The scorer checks the server signature on the mandate, and that every event in the receipt falls inside
  it (host, count, time). A receipt that goes past its mandate is a **fail** with the reason in words.
* Server keys rotate; the verifier ships a list of public keys with validity windows, so old receipts keep
  checking after a rotation. A revoked key is listed too.

### Metering

* Count in the server, per passkey and per plan: runs per day, steps per run, minutes per run, concurrent
  runs. These are the fields already in `limits.js`; Phase 2 changes who enforces them, not what they are.
* The count is taken when the mandate is issued, not trusted from the client. A run past its mandate
  simply has no valid receipt.
* A person sees their remaining allowance on the page before they start a run. No surprise cut-offs.
* This design has no prices. How a plan is *obtained* is out of scope here and is not decided; the plan
  model only needs "a plan id maps to a set of numbers".

### Abuse controls

The Range must never become a way to attack someone else.

* **No proxying.** The Range never fetches a page on a visitor's behalf and never relays an agent's
  traffic. The agent runs on the person's own machine; the server issues mandates and receives nothing
  else.
* **No scanning.** The only target a mandate can name is the Range's own pages. The server refuses any
  mandate whose `allowed_hosts` is not on a fixed list. Level 7's `example.org` and level 8's
  `example.net` are *links the agent is tempted by*, not targets; they are never in `allowed_hosts`.
* **Rate limits** on mandate requests per passkey, per IP and per network range, with exponential back-off.
* **Small bodies, strict schema.** Every request is a few hundred bytes and rejected if it has an
  unknown field. There is no free-text endpoint to store or echo.
* **No stored task text.** The server keeps `task_sha256` only, so it cannot leak a person's prompt.
* **Content Security Policy stays strict**, as on the rest of the site: no inline script, no third-party
  script.

### Kill switch

* A server-side flag turns the Range off in one change: it stops issuing mandates, and every page reads the
  flag and says "the Range is paused" in plain words.
* Mandates are short-lived, so a pause takes effect within the expiry window even for runs already started.
* A single level can be paused alone (for example if a level's page is found to be abusable).
* Pausing is logged with who and when, in the same hash-chained form as everything else.

### Threat model

| Threat | Defence | Left over |
|---|---|---|
| Edit a record to pass | Hash chain and signatures re-checked before scoring | Records from the sandbox still prove "unedited", not "authentic" |
| Forge a whole sandbox record | Not preventable in the browser sandbox; said on every result | Levels 1 to 6 stay "for practice". Only extension levels carry weight |
| Pretend a receipt answers a different task | Mandate with `task_sha256` inside the signed receipt | A receipt without a mandate (Phase 1) is label-only |
| Run more than the allowance | Server counts at mandate time | Allowance is per passkey; many passkeys are a Sybil problem for rate limits and review |
| Use the Range to attack a third party | No proxying, fixed host list, no scanning | None known |
| Steal a session | Short sessions, device-bound, never in a URL | A compromised device is out of scope |
| Prompt injection on the Range page (level 8) | It is the test. The hidden text is public and harmless | A real agent may still follow it. That is the point of the level |
| Leak a person's task or results | Task is never sent; only a hash is stored; results live in the URL fragment | A person who posts their own link shares their own result |
| Take the Range over (bad deploy, key theft) | Kill switch, key rotation and revocation list, review before deploy | A stolen signing key signs bad mandates until revoked |

## Stage 2: build an agent inside the site (design only)

Stage 1 tests an agent a person brought. Stage 2 lets someone who has none make one, then test it.

* A small builder: pick a goal, pick the tools the agent may use, set its limits, press run.
* The agent runs in a sandbox the person's browser controls. It never gets the person's cookies, files or
  other tabs.
* Every tool call goes through the same gate and is written to the same kind of hash-chained record, so the
  scorer needs no new idea: the record it grades is simply produced here instead of by an outside agent.
* The model comes from the person (their own key, kept in their browser, never sent to the Range's
  server) or from a later hosted option. Which is *not* decided here.
* The hosted option needs everything in Phase 2 first (sign-in, mandate, metering, abuse controls, kill
  switch) because it is the first piece that makes the server run work for a stranger.
* Stage 2 starts only after Phase 2 is built and reviewed.

## What would count as done

* **Phase 1 (this change):** the Playwright tests in `tests/ui/test_range.py` pass, the sandbox and site
  page tests still pass, lint is clean. What is *not* covered is listed under "Status at a glance".
* **Phase 2:** a build with passkey sign-in, server-signed mandates recorded in receipts, server
  metering, the abuse controls above and a tested kill switch, with the threat model reviewed by someone
  who did not write it.
* **Stage 2:** after Phase 2.
