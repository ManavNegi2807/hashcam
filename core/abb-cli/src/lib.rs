//! The `abb` command line: canonicalization, tree utilities, key generation,
//! the conformance-vector runner and `verify-global`.
//!
//! The CLI is the authoritative verifier (`R-REC-07`): a browser build may
//! never be the only way to check evidence. Arguments are parsed by hand so
//! that the dependency list stays short enough to licence-review.
//!
//! Exit codes come from `ERROR_HANDLING.md` section 9: 0 valid, 1 invalid,
//! 2 incomplete, 3 partial, 4 unsupported, 64 usage, 65 unreadable input,
//! 70 internal error. No command prints a private key.

#![forbid(unsafe_code)]

/// Base64 lives in `abb-jcs` with the other encoding helpers; re-exported
/// here because the vector runner and its tests use it.
pub use abb_jcs::b64;
pub mod approve;
pub mod vectors;
pub mod witness;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use abb_checkpoint::{key_id_for, tagged_bytes, tags, CheckpointPayload, KeyManifest, Role};
use abb_jcs::{hex_lower, Limits, Value};
use abb_merkle as merkle;

/// Usage error: the arguments did not make sense.
pub const EXIT_USAGE: i32 = 64;
/// Input could not be read or was rejected before any checking.
pub const EXIT_UNREADABLE: i32 = 65;
/// A check ran and failed.
pub const EXIT_INVALID: i32 = 1;
/// Everything asked for succeeded.
pub const EXIT_OK: i32 = 0;

const USAGE: &str = "\
abb - Agent Black Box command line (protocol abb/1)

USAGE:
  abb canon (<file> | --stdin) [--text] [--sha256]
  abb verify <receipt> [--keys <manifest>] [--profile LOCAL_ONLY|CONNECTED_EVIDENCE] [--json]
  abb receipt build --bundle <file> --out <file>
  abb witness sign --key <file> --state <file> --keys <manifest> --domain <label>
                   --checkpoint <file> --records <file>
  abb anchor append --file <file> --checkpoint <file>
  abb approve --key <file> --run-id <id> --action-id <id> --approval-id <id>
              --decision GRANTED|DENIED --expires-at <ms>
              (--summary <text> | --summary-digest <hex>)
  abb approval check --keys <manifest> --key-id <id> --statement-b64 <b64> --signature <hex>
  abb mandate sign --key <file> --file <mandate.json>
  abb mandate check --keys <manifest> --document-b64 <b64> --signature <hex>
  abb commit (--value-json <json> | --stdin) [--salt-hex <32 hex>]
  abb leaf --tag <ABB1-...> (--file <file> | --stdin)
  abb digest (--file <file> | --stdin)
  abb attest --key <file> (--file <file> | --stdin)
  abb event canon (--file <file> | --stdin) [--strict]
                  [--run-id <uuid> --event-id <uuid> --sequence <n> --created-at <ms>]
  abb merkle root (--synthetic <n> | --leaves <file>)
  abb merkle proof (--synthetic <n> | --leaves <file>) --index <i>
  abb merkle verify --leaf-hash <hex> --index <i> --size <n> --root <hex> [--path <hex,hex,...>]
  abb merkle consistency (--synthetic <n> | --leaves <file>) --first <m>
  abb merkle verify-consistency --first <m> --second <n> --first-root <hex> [--path <hex,...>]
  abb keygen --out <dir> [--role signer|witness|approver|mandate_issuer]
  abb vectors check [--dir <vectors dir>]
  abb verify-global --roots <file> [--anchor <file>] [--keys <manifest>]
  abb help | --version

`abb attest` canonicalizes a signer request and signs it with the ingestion
key, printing the exact body to POST. The service calls it so that the
request layout and its canonical form live in one place (D-20).

`abb event canon` validates one event envelope and prints its canonical bytes,
digest and Merkle leaf hash as key=value lines. The ingestion service calls it
so that there is only ever one implementation of the canonical rules.

A --leaves file holds one base64-encoded leaf per line.
No command ever prints a private key.
";

/// Parsed flags: `--name value` pairs plus bare words.
struct Args {
    words: Vec<String>,
    flags: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(raw: &[String]) -> Self {
        let mut words = Vec::new();
        let mut flags: Vec<(String, Option<String>)> = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            let item = &raw[i];
            if let Some(name) = item.strip_prefix("--") {
                let next = raw.get(i + 1);
                match next {
                    Some(value) if !value.starts_with("--") => {
                        flags.push((name.to_owned(), Some(value.clone())));
                        i += 2;
                    }
                    _ => {
                        flags.push((name.to_owned(), None));
                        i += 1;
                    }
                }
            } else {
                words.push(item.clone());
                i += 1;
            }
        }
        Self { words, flags }
    }

    fn word(&self, index: usize) -> Option<&str> {
        self.words.get(index).map(String::as_str)
    }

    fn flag(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn present(&self, name: &str) -> bool {
        self.flags.iter().any(|(n, _)| n == name)
    }

    fn number(&self, name: &str) -> Result<Option<usize>, String> {
        match self.flag(name) {
            None => Ok(None),
            Some(text) => text
                .parse::<usize>()
                .map(Some)
                .map_err(|_| format!("--{name} needs a non-negative integer, got {text}")),
        }
    }
}

/// Run the CLI. `raw` excludes the program name. Returns the exit code.
#[must_use]
pub fn run(raw: &[String], out: &mut impl Write, err: &mut impl Write) -> i32 {
    let args = Args::parse(raw);
    if args.present("version") {
        let _ = writeln!(
            out,
            "abb {} (protocol {})",
            env!("CARGO_PKG_VERSION"),
            abb_checkpoint::PROTOCOL_VERSION
        );
        return EXIT_OK;
    }
    match args.word(0) {
        None | Some("help") => {
            let _ = write!(out, "{USAGE}");
            if args.word(0).is_none() {
                return EXIT_USAGE;
            }
            EXIT_OK
        }
        Some("canon") => dispatch(cmd_canon(&args, out), err),
        Some("merkle") => dispatch(cmd_merkle(&args, out), err),
        Some("keygen") => dispatch(cmd_keygen(&args, out), err),
        Some("attest") => dispatch(cmd_attest(&args, out), err),
        Some("leaf") => dispatch(cmd_leaf(&args, out), err),
        Some("witness") => dispatch(cmd_witness(&args, out), err),
        Some("anchor") => dispatch(cmd_anchor(&args, out), err),
        Some("approve") => dispatch(approve::cmd_approve(&args, out, err), err),
        Some("approval") => dispatch(approve::cmd_approval(&args, out), err),
        Some("mandate") => dispatch(approve::cmd_mandate(&args, out), err),
        Some("commit") => dispatch(approve::cmd_commit(&args, out), err),
        Some("digest") => dispatch(cmd_digest(&args, out), err),
        Some("event") => dispatch(cmd_event(&args, out, err), err),
        Some("vectors") => dispatch(cmd_vectors(&args, out), err),
        Some("verify-global") => dispatch(cmd_verify_global(&args, out), err),
        Some("verify") => dispatch(cmd_verify(&args, out), err),
        Some("receipt") => dispatch(cmd_receipt(&args, out), err),
        Some(other) => {
            let _ = writeln!(err, "unknown command: {other}");
            let _ = write!(err, "{USAGE}");
            EXIT_USAGE
        }
    }
}

/// A command either produced an exit code or a message plus a code.
type CmdResult = Result<i32, (i32, String)>;

fn dispatch(result: CmdResult, err: &mut impl Write) -> i32 {
    match result {
        Ok(code) => code,
        Err((code, message)) => {
            let _ = writeln!(err, "{message}");
            code
        }
    }
}

fn usage(message: impl Into<String>) -> (i32, String) {
    (EXIT_USAGE, message.into())
}

fn unreadable(message: impl Into<String>) -> (i32, String) {
    (EXIT_UNREADABLE, message.into())
}

fn read_file(path: &str) -> Result<Vec<u8>, (i32, String)> {
    fs::read(path).map_err(|e| unreadable(format!("cannot read {path}: {e}")))
}

// --------------------------------------------------------------------------- //
// canon
// --------------------------------------------------------------------------- //

fn cmd_canon(args: &Args, out: &mut impl Write) -> CmdResult {
    let (path, bytes) = if args.present("stdin") {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut buffer)
            .map_err(|e| unreadable(format!("cannot read stdin: {e}")))?;
        ("<stdin>", buffer)
    } else {
        let path = args
            .word(1)
            .ok_or_else(|| usage("abb canon needs a file or --stdin"))?;
        let bytes = read_file(path)?;
        (path, bytes)
    };
    let value = abb_jcs::parse_bytes(&bytes, &Limits::protocol()).map_err(|e| {
        (
            EXIT_INVALID,
            format!("{path} is not acceptable protocol JSON: {e}"),
        )
    })?;
    let canonical = abb_jcs::canonical_bytes(&value)
        .map_err(|e| (EXIT_INVALID, format!("cannot canonicalize {path}: {e}")))?;

    if args.present("text") {
        let text = String::from_utf8(canonical.clone())
            .map_err(|e| (EXIT_INVALID, format!("canonical bytes are not UTF-8: {e}")))?;
        let _ = writeln!(out, "{text}");
    }
    if args.present("sha256") {
        let _ = writeln!(
            out,
            "{}",
            abb_jcs::canonical_sha256_hex(&value).unwrap_or_default()
        );
    }
    if !args.present("text") && !args.present("sha256") {
        // The contract says: print the JCS bytes as hex.
        let _ = writeln!(out, "{}", hex_lower(&canonical));
    }
    Ok(EXIT_OK)
}

/// `abb digest`: the artifact digest, `SHA-256(raw bytes)` with no tag (`D-03`).
fn cmd_digest(args: &Args, out: &mut impl Write) -> CmdResult {
    let data = if let Some(path) = args.flag("file") {
        read_file(path)?
    } else if args.present("stdin") {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut buffer)
            .map_err(|e| unreadable(format!("cannot read stdin: {e}")))?;
        buffer
    } else {
        return Err(usage("give --file <file> or --stdin"));
    };
    let _ = writeln!(out, "digest={}", hex_lower(&sha2_of(&data)));
    let _ = writeln!(out, "size={}", data.len());
    Ok(EXIT_OK)
}

/// Read a `{payload_b64, signature}` checkpoint file.
fn read_checkpoint_file(path: &str) -> Result<(Vec<u8>, String), (i32, String)> {
    let bytes = read_file(path)?;
    let value = abb_jcs::parse_bytes(&bytes, &abb_jcs::Limits::relaxed())
        .map_err(|e| unreadable(format!("{path}: {e}")))?;
    let payload = value
        .get("payload_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| unreadable(format!("{path}: no payload_b64")))?;
    let signature = value
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| unreadable(format!("{path}: no signature")))?;
    let payload = b64::decode(payload).map_err(|e| unreadable(format!("{path}: {e}")))?;
    Ok((payload, signature.to_owned()))
}

/// `abb witness sign`: co-sign a global checkpoint after checking it.
///
/// Meant to run on a different machine from the signer. It rebuilds the tree
/// from the records and keeps its own anti-rollback state; if it is run on the
/// signer's own machine it still works, and the verifier will then correctly
/// call the result NOT_INDEPENDENT.
fn cmd_witness(args: &Args, out: &mut impl Write) -> CmdResult {
    if args.word(1) != Some("sign") {
        return Err(usage("abb witness needs the subcommand sign"));
    }
    let need = |name: &str| {
        args.flag(name)
            .ok_or_else(|| usage(format!("abb witness sign needs --{name}")))
    };
    let key = witness::read_signing_key(Path::new(need("key")?)).map_err(unreadable)?;
    let state_path = PathBuf::from(need("state")?);
    let keys_path = need("keys")?;
    let domain = need("domain")?;
    let (payload, signature) = read_checkpoint_file(need("checkpoint")?)?;
    let records = witness::read_records(Path::new(need("records")?)).map_err(unreadable)?;

    let key_bytes = read_file(keys_path)?;
    let key_doc = abb_jcs::parse_bytes(&key_bytes, &abb_jcs::Limits::relaxed())
        .map_err(|e| unreadable(format!("{keys_path}: {e}")))?;
    let manifest = abb_checkpoint::KeyManifest::from_value(&key_doc)
        .map_err(|e| unreadable(format!("{keys_path}: {e}")))?;

    let previous = witness::load_state(&state_path)
        .map_err(|e| (EXIT_INVALID, format!("the witness state is unusable: {e}")))?;
    let witness_id = key_id_for(&key.verifying_key().to_bytes());

    let request = witness::Request {
        checkpoint_payload: &payload,
        checkpoint_signature: &signature,
        records: &records,
        keys: &manifest,
        previous,
        witness_id: &witness_id,
        failure_domain: domain,
        now_ms: abb_signer::now_ms(),
    };
    match witness::witness(&request, &key) {
        Err(refusal) => Err((EXIT_INVALID, format!("REFUSED {refusal}"))),
        Ok(done) => {
            // State first, then the signature: a witness that signs and then
            // loses its memory could sign a rollback next time.
            witness::save_state(&state_path, &done.state)
                .map_err(|e| (EXIT_INVALID, format!("cannot record state: {e}")))?;
            let _ = writeln!(out, "witness_id={witness_id}");
            let _ = writeln!(out, "statement_b64={}", b64::encode(&done.statement));
            let _ = writeln!(out, "signature={}", done.signature);
            let _ = writeln!(out, "tree_size={}", done.state.tree_size);
            Ok(EXIT_OK)
        }
    }
}

/// `abb anchor append`: add a global checkpoint to an append-only anchor file.
fn cmd_anchor(args: &Args, out: &mut impl Write) -> CmdResult {
    if args.word(1) != Some("append") {
        return Err(usage("abb anchor needs the subcommand append"));
    }
    let file = args
        .flag("file")
        .ok_or_else(|| usage("abb anchor append needs --file"))?;
    let cp = args
        .flag("checkpoint")
        .ok_or_else(|| usage("abb anchor append needs --checkpoint"))?;
    let (payload, _) = read_checkpoint_file(cp)?;
    let text = std::str::from_utf8(&payload).map_err(|e| unreadable(format!("{cp}: {e}")))?;
    let parsed = abb_checkpoint::CheckpointPayload::from_canonical(text)
        .map_err(|e| unreadable(format!("{cp}: {e}")))?;
    if parsed.stream_id != "global" {
        return Err((
            EXIT_INVALID,
            "only global checkpoints are anchored (D-10)".to_owned(),
        ));
    }
    let hash = parsed
        .checkpoint_hash_hex()
        .map_err(|e| unreadable(format!("{cp}: {e}")))?;
    let published_at = args
        .number("published-at")
        .map_err(usage)?
        .map_or_else(abb_signer::now_ms, |v| i64::try_from(v).unwrap_or(0));
    witness::anchor_append(Path::new(file), parsed.tree_size, &hash, published_at)
        .map_err(|e| (EXIT_INVALID, format!("REFUSED {e}")))?;
    let _ = writeln!(
        out,
        "anchored tree_size={} checkpoint_hash={hash}",
        parsed.tree_size
    );
    Ok(EXIT_OK)
}

/// `abb leaf`: the Merkle leaf hash of tagged data.
///
/// Exists so no caller has to reimplement `SHA-256(0x00 || tag || 0x00 || data)`.
/// The ingestion service uses it for global-log rows; the vectors use it too.
fn cmd_leaf(args: &Args, out: &mut impl Write) -> CmdResult {
    let tag = args
        .flag("tag")
        .ok_or_else(|| usage("abb leaf needs --tag <ABB1-...>"))?;
    if !abb_checkpoint::tags::ALL.contains(&tag) {
        return Err(usage(format!(
            "{tag} is not one of the nine abb/1 domain tags"
        )));
    }
    let data = if let Some(path) = args.flag("file") {
        read_file(path)?
    } else if args.present("stdin") {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut buffer)
            .map_err(|e| unreadable(format!("cannot read stdin: {e}")))?;
        buffer
    } else {
        return Err(usage("give --file <file> or --stdin"));
    };
    let tagged = abb_checkpoint::tagged_bytes(tag, &data);
    let _ = writeln!(out, "tagged_digest={}", hex_lower(&sha2_of(&tagged)));
    let _ = writeln!(
        out,
        "leaf_hash={}",
        hex_lower(&abb_merkle::leaf_hash(&tagged))
    );
    Ok(EXIT_OK)
}

// --------------------------------------------------------------------------- //
// verify and receipt build
// --------------------------------------------------------------------------- //

/// `abb receipt build`: turn an export bundle into a `*.abbreceipt`.
///
/// The bundle comes from the service, which knows the database. Every proof and
/// the canonical layout are computed here, so the service never hashes anything
/// itself (`R-PRO-04`).
fn cmd_receipt(args: &Args, out: &mut impl Write) -> CmdResult {
    if args.word(1) != Some("build") {
        return Err(usage("abb receipt needs the subcommand build"));
    }
    let bundle_path = args
        .flag("bundle")
        .ok_or_else(|| usage("abb receipt build needs --bundle <file>"))?;
    let out_path = args
        .flag("out")
        .ok_or_else(|| usage("abb receipt build needs --out <file>"))?;
    let bundle = read_file(bundle_path)?;

    let file = abb_receipt::build(&bundle)
        .map_err(|e| (EXIT_INVALID, format!("cannot build the receipt: {e}")))?;
    let container = abb_receipt::write_container(&file)
        .map_err(|e| (EXIT_INVALID, format!("cannot write the container: {e}")))?;
    std::fs::write(out_path, &container)
        .map_err(|e| unreadable(format!("cannot write {out_path}: {e}")))?;

    let _ = writeln!(out, "receipt={out_path}");
    let _ = writeln!(out, "bytes={}", container.len());
    let _ = writeln!(
        out,
        "receipt_json_sha256={}",
        hex_lower(&sha2_of(&file.receipt_json))
    );
    Ok(EXIT_OK)
}

/// `abb verify`: check a receipt offline and report every dimension.
///
/// This is the authoritative verifier (`R-REC-07`). It never stops at the first
/// failure, and it exits with the code for the overall result
/// (`ERROR_HANDLING.md` 9): 0 valid, 1 invalid, 2 incomplete, 3 partial,
/// 4 unsupported, and 65 for a file it refused to read at all.
fn cmd_verify(args: &Args, out: &mut impl Write) -> CmdResult {
    let path = args
        .word(1)
        .ok_or_else(|| usage("abb verify needs a receipt file"))?;
    let bytes = read_file(path)?;

    let profile = match args.flag("profile") {
        None => abb_verify::Profile::LocalOnly,
        Some(text) => abb_verify::Profile::parse(text)
            .ok_or_else(|| usage(format!("unknown profile {text}")))?,
    };

    // A container this build refuses is exit 65, before any verification: a
    // malformed or hostile archive is not an INVALID receipt, it is not a
    // receipt (TS-16).
    let file = abb_receipt::read_container(&bytes)
        .map_err(|e| (EXIT_UNREADABLE, format!("{path}: {e}")))?;

    let receipt = match abb_receipt::Receipt::parse(&file.receipt_json) {
        Ok(receipt) => receipt,
        Err(abb_receipt::ReceiptError::Unsupported(why)) => {
            let _ = writeln!(out, "overall=UNSUPPORTED");
            let _ = writeln!(out, "reason={why}");
            return Ok(abb_verify::Overall::Unsupported.exit_code());
        }
        Err(other) => {
            return Err((EXIT_UNREADABLE, format!("{path}: {other}")));
        }
    };

    // Keys come from a channel independent of the receipt (PROTOCOL.md 10.5).
    // Without them, signatures are UNKNOWN rather than assumed good.
    let keys = match args.flag("keys") {
        None => None,
        Some(keys_path) => {
            let key_bytes = read_file(keys_path)?;
            let value = abb_jcs::parse_bytes(&key_bytes, &abb_jcs::Limits::relaxed())
                .map_err(|e| unreadable(format!("{keys_path}: {e}")))?;
            Some(
                abb_checkpoint::KeyManifest::from_value(&value)
                    .map_err(|e| unreadable(format!("{keys_path}: {e}")))?,
            )
        }
    };

    let report = abb_receipt::verify_with(&receipt, keys.as_ref(), profile, &file.artifacts);

    if args.present("json") {
        let _ = writeln!(out, "{}", report_json(&report, &receipt));
    } else {
        let _ = writeln!(out, "receipt: {path}");
        let _ = writeln!(out, "run: {}", receipt.run_id);
        let _ = writeln!(
            out,
            "adapter: {} {} | profile: {} | declared coverage: {}",
            receipt.adapter_name,
            receipt.adapter_version,
            receipt.profile,
            receipt.declared_coverage
        );
        let _ = writeln!(out);
        for line in report.to_lines() {
            let _ = writeln!(out, "  {line}");
        }
        if !report.details.is_empty() {
            let _ = writeln!(out);
            for detail in &report.details {
                match &detail.locator {
                    Some(locator) => {
                        let _ = writeln!(
                            out,
                            "  {}: {} [{locator}]",
                            detail.dimension, detail.message
                        );
                    }
                    None => {
                        let _ = writeln!(out, "  {}: {}", detail.dimension, detail.message);
                    }
                }
            }
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", abb_receipt::summarize(&report));
        if keys.is_none() {
            let _ = writeln!(
                out,
                "\nNote: no --keys manifest was given, so no signature was checked."
            );
        }
    }
    Ok(report.overall().exit_code())
}

/// A stable JSON report, shaped like the verification response in the contracts.
fn report_json(report: &abb_verify::Report, receipt: &abb_receipt::Receipt) -> String {
    let dimensions: Vec<(String, Value)> = abb_verify::Dimension::ALL
        .iter()
        .map(|dim| {
            (
                dim.as_str().to_owned(),
                Value::Str(report.status(*dim).as_str().to_owned()),
            )
        })
        .collect();
    // How much each dimension counts in this report, so a viewer can show it
    // without keeping its own copy of the table (PROTOCOL.md 16.1).
    let requirements: Vec<(String, Value)> = abb_verify::Dimension::ALL
        .iter()
        .map(|dim| {
            let word = match report.requirement(*dim) {
                abb_verify::Requirement::Required => "required",
                abb_verify::Requirement::Optional => "optional",
                abb_verify::Requirement::Informational => "informational",
            };
            (dim.as_str().to_owned(), Value::Str(word.to_owned()))
        })
        .collect();
    let details: Vec<Value> = report
        .details
        .iter()
        .map(|detail| {
            let mut entries = vec![
                (
                    "dimension".to_owned(),
                    Value::Str(detail.dimension.as_str().to_owned()),
                ),
                ("message".to_owned(), Value::Str(detail.message.clone())),
            ];
            if let Some(locator) = &detail.locator {
                entries.push(("locator".to_owned(), Value::Str(locator.clone())));
            }
            Value::Object(entries)
        })
        .collect();
    let value = Value::Object(vec![
        (
            "overall".to_owned(),
            Value::Str(report.overall().as_str().to_owned()),
        ),
        ("run_id".to_owned(), Value::Str(receipt.run_id.clone())),
        ("profile".to_owned(), Value::Str(receipt.profile.clone())),
        (
            "declared_coverage".to_owned(),
            Value::Str(receipt.declared_coverage.clone()),
        ),
        ("dimensions".to_owned(), Value::Object(dimensions)),
        ("requirements".to_owned(), Value::Object(requirements)),
        ("details".to_owned(), Value::Array(details)),
    ]);
    abb_jcs::to_canonical_with(&value, &abb_jcs::Limits::relaxed())
        .unwrap_or_else(|_| "{\"overall\":\"INTERNAL\"}".to_owned())
}

// --------------------------------------------------------------------------- //
// attest
// --------------------------------------------------------------------------- //

/// `abb attest`: canonicalize a signer request and sign it with the ingestion
/// key (decision **D-20**).
///
/// Prints the complete request body to POST, so the caller never has to
/// canonicalize anything itself. The key is read from a file and never printed.
fn cmd_attest(args: &Args, out: &mut impl Write) -> CmdResult {
    let key_path = args
        .flag("key")
        .ok_or_else(|| usage("abb attest needs --key <file>"))?;
    let bytes = if let Some(path) = args.flag("file") {
        read_file(path)?
    } else if args.present("stdin") {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut buffer)
            .map_err(|e| unreadable(format!("cannot read stdin: {e}")))?;
        buffer
    } else {
        return Err(usage("give --file <file> or --stdin"));
    };

    let seed = read_file(key_path)?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| unreadable("the key file must hold exactly 32 bytes"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);

    let request = abb_jcs::parse_bytes(&bytes, &abb_jcs::Limits::relaxed()).map_err(|e| {
        (
            EXIT_INVALID,
            format!("the request is not acceptable JSON: {e}"),
        )
    })?;
    let signing_bytes = abb_signer::request_signing_bytes(&request)
        .map_err(|e| (EXIT_INVALID, format!("cannot build the signing bytes: {e}")))?;
    let signature = {
        use ed25519_dalek::Signer as _;
        hex_lower(&signing.sign(&signing_bytes).to_bytes())
    };

    // Rebuild the body with the attestation attached, canonically.
    let entries = request
        .as_object()
        .ok_or_else(|| usage("the request must be a JSON object"))?;
    let mut with_attestation: Vec<(String, Value)> = entries
        .iter()
        .filter(|(key, _)| key != "caller_attestation")
        .cloned()
        .collect();
    with_attestation.push((
        "caller_attestation".to_owned(),
        Value::Str(signature.clone()),
    ));
    let body = abb_jcs::to_canonical_with(
        &Value::Object(with_attestation),
        &abb_jcs::Limits::relaxed(),
    )
    .map_err(|e| (EXIT_INVALID, format!("cannot canonicalize the body: {e}")))?;

    let _ = writeln!(out, "signature={signature}");
    let _ = writeln!(out, "body_hex={}", hex_lower(body.as_bytes()));
    Ok(EXIT_OK)
}

// --------------------------------------------------------------------------- //
// event
// --------------------------------------------------------------------------- //

/// `abb event canon`: validate one event envelope and report what the
/// ingestion service needs to commit it.
///
/// Exit 0 with key=value lines on stdout, or exit 1 with `error_code=<CODE>` on
/// stderr. The service maps that code straight onto its HTTP error code, so
/// there is exactly one place where the envelope rules live (R-PRO-04,
/// AGENTS.md 3.10).
fn cmd_event(args: &Args, out: &mut impl Write, err: &mut impl Write) -> CmdResult {
    if args.word(1) != Some("canon") {
        return Err(usage("abb event needs the subcommand canon"));
    }
    let bytes = if let Some(path) = args.flag("file") {
        read_file(path)?
    } else if args.present("stdin") {
        let mut buffer = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut buffer)
            .map_err(|e| unreadable(format!("cannot read stdin: {e}")))?;
        buffer
    } else {
        return Err(usage("give --file <file> or --stdin"));
    };

    // Three modes. --strict is the signer's rule (bytes already canonical).
    // With the assignment flags this is the ingestion path: the producer's raw
    // bytes plus the fields only the server may choose. Otherwise it just
    // canonicalizes and validates what it was given.
    let validated = if args.present("strict") {
        abb_event::validate(&bytes)
    } else if let Some(run_id) = args.flag("run-id") {
        let event_id = args
            .flag("event-id")
            .ok_or_else(|| usage("--event-id is required with --run-id"))?;
        let sequence = args
            .number("sequence")
            .map_err(usage)?
            .ok_or_else(|| usage("--sequence is required with --run-id"))?;
        let created_at = args
            .number("created-at")
            .map_err(usage)?
            .ok_or_else(|| usage("--created-at is required with --run-id"))?;
        let assignment = abb_event::Assignment {
            run_id: run_id.to_owned(),
            event_id: event_id.to_owned(),
            sequence: i64::try_from(sequence).map_err(|_| usage("--sequence out of range"))?,
            created_at: i64::try_from(created_at)
                .map_err(|_| usage("--created-at out of range"))?,
        };
        abb_event::assign_and_validate(&bytes, &assignment)
    } else {
        abb_event::canonicalize_and_validate(&bytes)
    };
    match validated {
        Err(error) => {
            let _ = writeln!(err, "error_code={}", error.as_str());
            let _ = writeln!(err, "error_detail={error}");
            Ok(EXIT_INVALID)
        }
        Ok(event) => {
            let _ = writeln!(out, "canonical_hex={}", hex_lower(&event.canonical));
            let _ = writeln!(
                out,
                "canonical_sha256={}",
                hex_lower(&sha2_of(&event.canonical))
            );
            let _ = writeln!(out, "leaf_hash={}", hex_lower(&event.leaf_hash));
            let _ = writeln!(out, "run_id={}", event.run_id);
            let _ = writeln!(out, "event_id={}", event.event_id);
            let _ = writeln!(out, "sequence={}", event.sequence);
            let _ = writeln!(out, "event_type={}", event.event_type);
            let _ = writeln!(out, "source={}", event.source);
            let _ = writeln!(out, "created_at={}", event.created_at);
            if let Some(key) = &event.idempotency_key {
                let _ = writeln!(out, "idempotency_key={key}");
            }
            Ok(EXIT_OK)
        }
    }
}

fn sha2_of(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(data).into()
}

// --------------------------------------------------------------------------- //
// merkle
// --------------------------------------------------------------------------- //

fn leaves_from(args: &Args) -> Result<Vec<Vec<u8>>, (i32, String)> {
    if let Some(count) = args.number("synthetic").map_err(usage)? {
        return Ok(merkle::synthetic_leaves(count));
    }
    let path = args
        .flag("leaves")
        .ok_or_else(|| usage("give either --synthetic <n> or --leaves <file>"))?;
    let text = String::from_utf8(read_file(path)?)
        .map_err(|e| unreadable(format!("{path} is not UTF-8: {e}")))?;
    let mut leaves = Vec::new();
    for (line_no, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let decoded = b64::decode(trimmed)
            .map_err(|e| unreadable(format!("{path} line {}: {e}", line_no + 1)))?;
        leaves.push(decoded);
    }
    Ok(leaves)
}

fn hash_arg(args: &Args, name: &str) -> Result<[u8; 32], (i32, String)> {
    let text = args
        .flag(name)
        .ok_or_else(|| usage(format!("--{name} is required")))?;
    let raw = abb_jcs::hex_decode(text)
        .map_err(|_| usage(format!("--{name} must be 64 lowercase hex characters")))?;
    raw.try_into()
        .map_err(|_| usage(format!("--{name} must be 32 bytes")))
}

fn path_arg(args: &Args) -> Result<Vec<[u8; 32]>, (i32, String)> {
    let Some(text) = args.flag("path") else {
        return Ok(Vec::new());
    };
    if text.is_empty() {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|part| {
            let raw = abb_jcs::hex_decode(part.trim())
                .map_err(|_| usage("--path elements must be 64 lowercase hex characters"))?;
            raw.try_into()
                .map_err(|_| usage("--path elements must be 32 bytes"))
        })
        .collect()
}

fn cmd_merkle(args: &Args, out: &mut impl Write) -> CmdResult {
    match args.word(1) {
        Some("root") => {
            let leaves = leaves_from(args)?;
            let _ = writeln!(out, "{}", hex_lower(&merkle::mth(&leaves)));
            Ok(EXIT_OK)
        }
        Some("proof") => {
            let leaves = leaves_from(args)?;
            let index = args
                .number("index")
                .map_err(usage)?
                .ok_or_else(|| usage("--index is required"))?;
            let path = merkle::inclusion_path(index, &leaves)
                .map_err(|e| (EXIT_INVALID, format!("cannot build the path: {e}")))?;
            let hexes: Vec<String> = path.iter().map(|h| hex_lower(h)).collect();
            let _ = writeln!(
                out,
                "leaf_index={index} tree_size={} root={} path={}",
                leaves.len(),
                hex_lower(&merkle::mth(&leaves)),
                hexes.join(",")
            );
            Ok(EXIT_OK)
        }
        Some("verify") => {
            let leaf = hash_arg(args, "leaf-hash")?;
            let root = hash_arg(args, "root")?;
            let index = args
                .number("index")
                .map_err(usage)?
                .ok_or_else(|| usage("--index is required"))?;
            let size = args
                .number("size")
                .map_err(usage)?
                .ok_or_else(|| usage("--size is required"))?;
            let path = path_arg(args)?;
            match merkle::verify_inclusion(&leaf, index as u64, size as u64, &path) {
                Ok(derived) if derived == root => {
                    let _ = writeln!(out, "INCLUDED leaf_index={index} tree_size={size}");
                    Ok(EXIT_OK)
                }
                Ok(derived) => {
                    let _ = writeln!(
                        out,
                        "NOT_INCLUDED derived_root={} expected_root={}",
                        hex_lower(&derived),
                        hex_lower(&root)
                    );
                    Ok(EXIT_INVALID)
                }
                Err(e) => {
                    let _ = writeln!(out, "REJECTED {e}");
                    Ok(EXIT_INVALID)
                }
            }
        }
        Some("consistency") => {
            let leaves = leaves_from(args)?;
            let first = args
                .number("first")
                .map_err(usage)?
                .ok_or_else(|| usage("--first is required"))?;
            let path = merkle::consistency_path(first, &leaves)
                .map_err(|e| (EXIT_INVALID, format!("cannot build the proof: {e}")))?;
            let hexes: Vec<String> = path.iter().map(|h| hex_lower(h)).collect();
            let _ = writeln!(
                out,
                "first_size={first} second_size={} first_root={} second_root={} path={}",
                leaves.len(),
                hex_lower(&merkle::mth(&merkle::synthetic_leaves(first).to_vec())),
                hex_lower(&merkle::mth(&leaves)),
                hexes.join(",")
            );
            Ok(EXIT_OK)
        }
        Some("verify-consistency") => {
            let first = args
                .number("first")
                .map_err(usage)?
                .ok_or_else(|| usage("--first is required"))?;
            let second = args
                .number("second")
                .map_err(usage)?
                .ok_or_else(|| usage("--second is required"))?;
            let first_root = hash_arg(args, "first-root")?;
            let path = path_arg(args)?;
            match merkle::verify_consistency(first as u64, second as u64, &first_root, &path) {
                Ok(second_root) => {
                    let _ = writeln!(out, "CONSISTENT second_root={}", hex_lower(&second_root));
                    Ok(EXIT_OK)
                }
                Err(e) => {
                    let _ = writeln!(out, "REJECTED {e}");
                    Ok(EXIT_INVALID)
                }
            }
        }
        _ => Err(usage(
            "abb merkle needs root, proof, verify, consistency or verify-consistency",
        )),
    }
}

// --------------------------------------------------------------------------- //
// keygen
// --------------------------------------------------------------------------- //

fn cmd_keygen(args: &Args, out: &mut impl Write) -> CmdResult {
    let dir = args
        .flag("out")
        .ok_or_else(|| usage("abb keygen needs --out <dir>"))?;
    let role_text = args.flag("role").unwrap_or("signer");
    let role = Role::parse(role_text).ok_or_else(|| usage(format!("unknown role {role_text}")))?;
    let dir_path = PathBuf::from(dir);
    fs::create_dir_all(&dir_path).map_err(|e| unreadable(format!("cannot create {dir}: {e}")))?;

    let private_path = dir_path.join(format!("{role_text}.key"));
    let public_path = dir_path.join(format!("{role_text}.pub"));
    for path in [&private_path, &public_path] {
        if path.exists() {
            return Err((
                EXIT_USAGE,
                format!(
                    "{} already exists; refusing to overwrite a key",
                    path.display()
                ),
            ));
        }
    }

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| (70, format!("no secure randomness available: {e}")))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let public = signing.verifying_key().to_bytes();
    let key_id = key_id_for(&public);

    // The private key is written to a file and never printed, logged or
    // returned (AGENTS.md 3.14).
    fs::write(&private_path, seed)
        .map_err(|e| unreadable(format!("cannot write the key file: {e}")))?;
    fs::write(&public_path, format!("{}\n", hex_lower(&public)))
        .map_err(|e| unreadable(format!("cannot write the public key: {e}")))?;
    restrict_permissions(&private_path, out);

    let _ = writeln!(out, "role={role_text}");
    let _ = writeln!(out, "key_id={key_id}");
    let _ = writeln!(out, "public_key_hex={}", hex_lower(&public));
    let _ = writeln!(out, "private_key_file={}", private_path.display());
    let _ = writeln!(
        out,
        "The private key was written to that file only. Back it up offline and never commit it."
    );
    debug_assert_eq!(role.as_str(), role_text);
    Ok(EXIT_OK)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path, _out: &mut impl Write) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(path: &Path, out: &mut impl Write) {
    // Windows ACLs are not set here, so say so rather than implying the file
    // is protected.
    let _ = writeln!(
        out,
        "note: file permissions were not restricted on this platform; protect {} yourself",
        path.display()
    );
}

// --------------------------------------------------------------------------- //
// vectors
// --------------------------------------------------------------------------- //

fn default_vectors_dir() -> PathBuf {
    // The repository layout is core/abb-cli/, so vectors/ is two levels up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("vectors")
}

fn cmd_vectors(args: &Args, out: &mut impl Write) -> CmdResult {
    if args.word(1) != Some("check") {
        return Err(usage("abb vectors needs the subcommand check"));
    }
    let dir = args
        .flag("dir")
        .map_or_else(default_vectors_dir, PathBuf::from);
    let outcomes = vectors::check_all(&dir).map_err(|e| unreadable(format!("{e}")))?;
    let (passed, failed) = vectors::totals(&outcomes);
    for outcome in &outcomes {
        let _ = writeln!(
            out,
            "{:<28} {} passed, {} failed",
            outcome.file,
            outcome.passed,
            outcome.failures.len()
        );
        for failure in &outcome.failures {
            let _ = writeln!(out, "    {failure}");
        }
    }
    let _ = writeln!(out, "total: {passed} passed, {failed} failed");
    if failed == 0 {
        Ok(EXIT_OK)
    } else {
        Ok(EXIT_INVALID)
    }
}

// --------------------------------------------------------------------------- //
// verify-global
// --------------------------------------------------------------------------- //

fn cmd_verify_global(args: &Args, out: &mut impl Write) -> CmdResult {
    let roots_path = args
        .flag("roots")
        .ok_or_else(|| usage("abb verify-global needs --roots <file>"))?;
    let bytes = read_file(roots_path)?;
    let doc = abb_jcs::parse_bytes(&bytes, &Limits::relaxed())
        .map_err(|e| unreadable(format!("{roots_path}: {e}")))?;

    let records = doc
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| unreadable(format!("{roots_path}: no records array")))?;
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(records.len());
    for (position, record) in records.iter().enumerate() {
        let encoded = record
            .get("record_canonical_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| unreadable(format!("record {position} has no record_canonical_b64")))?;
        let canonical =
            b64::decode(encoded).map_err(|e| unreadable(format!("record {position}: {e}")))?;
        leaves.push(tagged_bytes(tags::RUNROOT, &canonical));
    }
    let recomputed = merkle::mth(&leaves);
    let _ = writeln!(out, "runs_in_log={}", leaves.len());
    let _ = writeln!(out, "recomputed_global_root={}", hex_lower(&recomputed));

    let mut problems: Vec<String> = Vec::new();

    // The global checkpoint the deployment last obtained.
    let checkpoint = doc.get("global_checkpoint").ok_or_else(|| {
        unreadable(format!(
            "{roots_path}: no global_checkpoint to compare against"
        ))
    })?;
    let encoded = checkpoint
        .get("canonical_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| unreadable("global_checkpoint has no canonical_b64"))?;
    let canonical =
        b64::decode(encoded).map_err(|e| unreadable(format!("global_checkpoint: {e}")))?;
    let text = std::str::from_utf8(&canonical)
        .map_err(|e| unreadable(format!("global_checkpoint: {e}")))?;
    let payload = CheckpointPayload::from_canonical(text)
        .map_err(|e| unreadable(format!("global_checkpoint: {e}")))?;
    let checkpoint_hash = payload
        .checkpoint_hash_hex()
        .map_err(|e| unreadable(format!("global_checkpoint: {e}")))?;
    let _ = writeln!(out, "checkpoint_tree_size={}", payload.tree_size);
    let _ = writeln!(out, "checkpoint_hash={checkpoint_hash}");

    if payload.stream_id != "global" {
        problems.push(format!(
            "checkpoint stream_id is {}, expected global",
            payload.stream_id
        ));
    }
    if payload.root_hash != hex_lower(&recomputed) {
        problems.push(format!(
            "GLOBAL_ROOT_MISMATCH: the log recomputes to {} but the checkpoint says {}",
            hex_lower(&recomputed),
            payload.root_hash
        ));
    }
    let present = i64::try_from(leaves.len()).unwrap_or(i64::MAX);
    if present < payload.tree_size {
        problems.push(format!(
            "MISSING_RUNS: the checkpoint covers {} runs but only {present} are in the log; \
             {} run(s) are gone",
            payload.tree_size,
            payload.tree_size - present
        ));
    }

    // The signature, when a key manifest is supplied.
    match args.flag("keys") {
        None => {
            let _ = writeln!(
                out,
                "checkpoint_signature=UNKNOWN (no --keys manifest given; the signature was not checked)"
            );
        }
        Some(keys_path) => {
            let key_bytes = read_file(keys_path)?;
            let key_doc = abb_jcs::parse_bytes(&key_bytes, &Limits::relaxed())
                .map_err(|e| unreadable(format!("{keys_path}: {e}")))?;
            let manifest = KeyManifest::from_value(&key_doc)
                .map_err(|e| unreadable(format!("{keys_path}: {e}")))?;
            let signature = checkpoint
                .get("signature")
                .and_then(Value::as_str)
                .unwrap_or("");
            match manifest.require(&payload.key_id, Role::Signer) {
                Err(e) => problems.push(format!("signer key rejected: {e}")),
                Ok(entry) => match entry.verifying_key() {
                    Err(e) => problems.push(format!("signer key unusable: {e}")),
                    Ok(verifying) => match payload.verify(signature, &verifying) {
                        Ok(()) => {
                            let _ = writeln!(out, "checkpoint_signature=PASS");
                        }
                        Err(e) => problems.push(format!("checkpoint signature failed: {e}")),
                    },
                },
            }
        }
    }

    // The anchor, when one is supplied.
    match args.flag("anchor") {
        None => {
            let _ = writeln!(
                out,
                "anchor=UNKNOWN (no --anchor given; a local comparison alone cannot detect a \
                 rollback of this machine)"
            );
        }
        Some(anchor_path) => {
            let anchor_text = String::from_utf8(read_file(anchor_path)?)
                .map_err(|e| unreadable(format!("{anchor_path}: {e}")))?;
            match last_anchor_line(&anchor_text) {
                None => problems.push(format!("{anchor_path} has no anchor lines")),
                Some((anchored_size, anchored_hash)) => {
                    let _ = writeln!(
                        out,
                        "anchored_tree_size={anchored_size} anchored_checkpoint_hash={anchored_hash}"
                    );
                    if anchored_hash != checkpoint_hash {
                        problems.push(format!(
                            "ANCHOR_MISMATCH: the anchor published {anchored_hash} but this \
                             checkpoint hashes to {checkpoint_hash}"
                        ));
                    }
                    if anchored_size > present {
                        problems.push(format!(
                            "MISSING_RUNS: the anchor covers {anchored_size} runs but only \
                             {present} are in the log"
                        ));
                    }
                }
            }
        }
    }

    if problems.is_empty() {
        let _ = writeln!(out, "result=OK (no missing or altered run detected)");
        Ok(EXIT_OK)
    } else {
        for problem in &problems {
            let _ = writeln!(out, "PROBLEM {problem}");
        }
        let _ = writeln!(out, "result=INVALID ({} problem(s))", problems.len());
        Ok(EXIT_INVALID)
    }
}

/// Read the last `tree_size checkpoint_hash published_at` line of an anchor file.
fn last_anchor_line(text: &str) -> Option<(i64, String)> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let size = parts.next()?.parse::<i64>().ok()?;
            let hash = parts.next()?.to_owned();
            Some((size, hash))
        })
        .next_back()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_cli(args: &[&str]) -> (i32, String, String) {
        let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run(&owned, &mut out, &mut err);
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[test]
    fn no_arguments_prints_usage_and_a_usage_code() {
        let (code, out, _) = run_cli(&[]);
        assert_eq!(code, EXIT_USAGE);
        assert!(out.contains("USAGE"));
    }

    #[test]
    fn unknown_command_is_a_usage_error() {
        let (code, _, err) = run_cli(&["frobnicate"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("unknown command"));
    }

    #[test]
    fn verify_refuses_a_file_that_is_not_a_receipt() {
        // Exit 65 is "I would not read that", which is not the same as INVALID.
        let temp = std::env::temp_dir().join(format!("abb-notareceipt-{}", std::process::id()));
        std::fs::write(&temp, b"this is not a zip").expect("write");
        let (code, out, err) = run_cli(&["verify", &temp.to_string_lossy()]);
        assert_eq!(code, EXIT_UNREADABLE, "{out}{err}");
        assert!(!out.contains("VALID"), "{out}");
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn verify_needs_a_file() {
        let (code, _, err) = run_cli(&["verify"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("receipt"), "{err}");
    }

    #[test]
    fn missing_file_is_exit_65() {
        let (code, _, err) = run_cli(&["canon", "no-such-file.json"]);
        assert_eq!(code, EXIT_UNREADABLE);
        assert!(err.contains("cannot read"));
    }

    #[test]
    fn merkle_root_of_synthetic_leaves_matches_the_library() {
        let (code, out, _) = run_cli(&["merkle", "root", "--synthetic", "7"]);
        assert_eq!(code, EXIT_OK);
        assert_eq!(
            out.trim(),
            hex_lower(&merkle::mth(&merkle::synthetic_leaves(7)))
        );
    }

    #[test]
    fn merkle_verify_reports_inclusion_and_rejects_a_wrong_root() {
        let leaves = merkle::synthetic_leaves(9);
        let path = merkle::inclusion_path(4, &leaves).unwrap();
        let path_arg = path
            .iter()
            .map(|h| hex_lower(h))
            .collect::<Vec<_>>()
            .join(",");
        let leaf = hex_lower(&merkle::leaf_hash(&leaves[4]));
        let root = hex_lower(&merkle::mth(&leaves));
        let (code, out, _) = run_cli(&[
            "merkle",
            "verify",
            "--leaf-hash",
            &leaf,
            "--index",
            "4",
            "--size",
            "9",
            "--root",
            &root,
            "--path",
            &path_arg,
        ]);
        assert_eq!(code, EXIT_OK, "{out}");
        assert!(out.contains("INCLUDED"));

        let wrong = "ab".repeat(32);
        let (code, out, _) = run_cli(&[
            "merkle",
            "verify",
            "--leaf-hash",
            &leaf,
            "--index",
            "4",
            "--size",
            "9",
            "--root",
            &wrong,
            "--path",
            &path_arg,
        ]);
        assert_eq!(code, EXIT_INVALID);
        assert!(out.contains("NOT_INCLUDED"));
    }

    #[test]
    fn bad_hex_in_an_argument_is_a_usage_error() {
        let (code, _, err) = run_cli(&[
            "merkle",
            "verify",
            "--leaf-hash",
            "zz",
            "--index",
            "0",
            "--size",
            "1",
            "--root",
            "aa",
        ]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("hex"));
    }

    #[test]
    fn anchor_parsing_takes_the_last_line_and_ignores_comments() {
        let text = "# tree_size checkpoint_hash published_at\n1 aa 100\n2 bb 200\n\n";
        assert_eq!(last_anchor_line(text), Some((2, "bb".to_owned())));
        assert_eq!(last_anchor_line("# only a comment\n"), None);
    }
}
