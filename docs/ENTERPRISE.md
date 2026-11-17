# HashCam Enterprise console: roles, companies and customer-issue analytics

The company console is `site/enterprise.html`. It is for people who hold a company access key, so it has its own
sidebar look and is **not linked from the public menu** (it is marked `noindex`). Everything runs in the browser.
**There is no server**, so none of it is enforced; each part below says whether it is `BUILT`, `PLANNED` or `NOT ENFORCED`.

## The three signed notes (Ed25519, checked with WebCrypto)

| Token | Signed by | Carries |
|---|---|---|
| `HCORG1` company certificate | the site **owner** key (`site/pro/pubkey.js`) | `org_id`, `org_name`, `org_pubkey`, dates |
| `HCMEM1` access key | the **company** key | `org_id`, `member_id` (unique), `name`, `role` (`boss` / `member`), `scopes[]`, `expires_at` |
| `HCREV1` revocation list | the **company** key | `org_id`, revoked `member_id`s |

Making them (on the company admin's computer; private keys are never printed and are refused inside the repo):

```bash
python tools/make_license.py org-init --org-id acme --org-name "Acme Ltd"
python tools/make_license.py member --org-id acme --role boss --name Dana
python tools/make_license.py member --org-id acme --role member --name Sam
python tools/make_license.py revoke --org-id acme --member-id m-1a2b3c4d
```

Only `org-init` needs the owner key, once per company. After that the company's admin makes member keys with the
**company** key, so the owner private key is never handed out.

## Roles

| | Boss (admin) | Member (maintainer) |
|---|---|---|
| Check customer records, triage assigned issues, notes, reproduce in the sandbox | yes | yes |
| See all issues and assign them | yes | only the ones assigned to them |
| Members and keys, policy defaults, approve or reject escalated holds, insights | yes | shown but locked (`<fieldset disabled>`) |

A key that asks for more than its role may have (for example a Member with `policy`) is refused, even if it is correctly signed.

## Customer issues (`site/pro/insights.js`)

Drop a customer's record (`.abbreceipt` with its `.keys.json`, or a sandbox receipt) and, optionally, `name.issue.json`
(`{"format":"hashcam-issue/1","category":"WASM_LOAD","note":"..."}`). Every record is **verified first**. A bundle with a
record that does not check out, or with no record, is **NOT INCLUDED**: listed with its reason, tallied beside the
verified count, never ranked. Categories: `WASM_LOAD`, `SIGNATURE_INVALID`, `CHAIN_BROKEN`, `POLICY_HOLD_TIMEOUT`,
`DOMAIN_ALERT`. A category is the customer's claim, or a guess from the verified record's words: a signal, not proof.

## Status

- `BUILT`: certificates, member keys with unique ids, roles and scopes, expiry, signed revocation lists, per-company storage prefix, Boss and Member views, issue triage, escalation notes, verified-only analytics.
- `NOT ENFORCED`: one company cannot open another's workspace *through this page*, but anyone with the browser's developer tools can read the browser's storage; a revoked key stops working only where the signed list was imported; policy defaults and escalation decisions are notes kept in one browser (not signed, not shared between devices).
- `PLANNED`: a server for real access control and shared data, single sign-on, signed audit logs, applying the company policy to a real gateway.

Not legal or compliance advice. Reports and counts are summaries, not proofs.
