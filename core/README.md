# core — Rust cryptographic core and the `abb` CLI

**Status:** `TESTED` for what is listed as built below; `SPECIFIED` for the rest.
**Built in:** Step 2 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-CRY-01..06, R-PRO-02/03/06, R-REC-02..05, R-REC-07, R-GLB-05, R-TST-01.

One core serves the signer, the CLI and a later WASM build. Wrappers must not
reimplement cryptographic rules (`AGENTS.md` 3.10). The CLI is the
authoritative verifier; a browser build may never be the only way to check a
receipt (`R-REC-07`).

## Crates

| Crate | What it owns | State |
|---|---|---|
| `abb-jcs` | RFC 8785 canonical JSON, the strict parser, hex helpers. **Owns the canonical bytes**; no third-party JSON crate is used | 15 unit tests |
| `abb-merkle` | RFC 6962 tree hash, the signer's incremental frontier, audit and consistency proofs plus their verifiers | 14 unit + 7 property tests |
| `abb-checkpoint` | The nine domain tags, checkpoint payload and signing, chain rules, key manifest with roles and `failure_domain`, rotation records | 14 unit tests |
| `abb-verify` | The 16 dimensions, the per-profile required/optional table, the overall-result precedence. No cryptography | 20 unit tests |
| `abb-cli` | The `abb` binary: `canon`, `merkle`, `keygen`, `vectors check`, `verify-global` | 11 unit + 8 integration tests |

## Commands

```bash
cargo run -q -p abb-cli -- vectors check      # the Step 2 acceptance check
cargo run -q -p abb-cli -- canon <file> [--text] [--sha256]
cargo run -q -p abb-cli -- merkle root --synthetic 7
cargo run -q -p abb-cli -- merkle proof --synthetic 9 --index 4
cargo run -q -p abb-cli -- merkle verify --leaf-hash <hex> --index 4 --size 9 --root <hex> --path <hex,hex>
cargo run -q -p abb-cli -- merkle consistency --synthetic 9 --first 4
cargo run -q -p abb-cli -- keygen --out secrets/signer --role signer
cargo run -q -p abb-cli -- verify-global --roots <file> [--anchor <file>] [--keys <manifest>]
```

`abb verify <receipt>` is **not implemented**: receipts do not exist until
Step 5. The command exists only to say so and exits 64; it never prints a
result.

Exit codes follow `ERROR_HANDLING.md` section 9: 0 valid, 1 invalid, 2
incomplete, 3 partial, 4 unsupported, 64 usage, 65 unreadable input, 70
internal.

## Building and testing

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -q -p abb-cli -- vectors check
```

**Windows note.** If the checkout sits under a long path, `link.exe` fails with
`LNK1104` because the output path passes the 260-character limit. Build with a
short target directory:

```bash
CARGO_TARGET_DIR=C:/abb-target cargo test --workspace
```

This is a local build convenience only; it changes nothing about the code.

## Dependencies and licences

Pinned in the workspace manifest and reviewed (`AGENTS.md` 3.11):

| Crate | Version | Licence |
|---|---|---|
| `sha2` | 0.10.9 | MIT OR Apache-2.0 |
| `ed25519-dalek` | 2.2.0 | BSD-3-Clause |
| `getrandom` | 0.3.3 | MIT OR Apache-2.0 |
| `proptest` (dev only) | 1.8.0 | MIT OR Apache-2.0 |

Transitively: `curve25519-dalek` (BSD-3-Clause), `signature`, `zeroize`,
`generic-array`, `typenum`, `cpufeatures`, `cfg-if` (MIT OR Apache-2.0). No
BSL, SSPL, AGPL or non-commercial dependency. JSON and JCS are hand written so
that no external crate owns the bytes that get signed.

Signature verification uses `verify_strict`, which rejects the small-order and
non-canonical points that plain Ed25519 verification accepts.

## What is deliberately absent

* `abb verify` and receipt parsing — Step 5.
* The signer service and its `append` validation — Step 4 (`signer/`).
* Field commitments, approvals and mandates — Step 9.
* The WASM build — deferred (`R-HKC-04`). Do not claim CLI and WASM agree.
* A database-backed `verify-global`; today it reads a file of run roots, and
  without `--anchor` it says the rollback question is `UNKNOWN` rather than OK.
