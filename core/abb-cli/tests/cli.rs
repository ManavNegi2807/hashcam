//! End-to-end tests for the `abb` library entry point.
//!
//! These call [`abb_cli::run`] rather than spawning the binary, so they work
//! the same in CI and on a developer machine. Two obligations are tested here
//! and nowhere else:
//!
//! * `abb vectors check` passes on the frozen vectors — the Step 2 acceptance
//!   check (`R-PRO-01`, `R-TST-01`);
//! * `abb verify-global` detects a deleted run (`R-GLB-05`, tamper case
//!   TS-11), against a file-backed global log; the database-backed form
//!   arrives with Step 3.

use std::path::{Path, PathBuf};

use abb_checkpoint::{tagged_bytes, tags, CheckpointPayload, ZERO_HASH_HEX};
use abb_jcs::{hex_lower, Value};
use abb_merkle as merkle;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn vectors_dir() -> PathBuf {
    repo_root().join("vectors")
}

fn call(args: &[&str]) -> (i32, String, String) {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = abb_cli::run(&owned, &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

#[test]
fn vectors_check_passes_on_the_frozen_vectors() {
    let dir = vectors_dir();
    assert!(dir.is_dir(), "vectors/ not found at {}", dir.display());
    let (code, out, err) = call(&["vectors", "check", "--dir", &dir.to_string_lossy()]);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("0 failed"), "{out}");
    // Every frozen set must be exercised, so a silently skipped file is caught.
    for file in [
        "jcs/canonical.json",
        "jcs/invalid.json",
        "hashing/domain_tags.json",
        "hashing/tree_hashes.json",
        "merkle/roots.json",
        "merkle/inclusion.json",
        "merkle/consistency.json",
        "merkle/malformed.json",
        "checkpoint/checkpoints.json",
        "global/global_log.json",
        "approval/approvals.json",
        "mandate/mandates.json",
        "commitment/commitments.json",
    ] {
        assert!(out.contains(file), "{file} was not run:\n{out}");
    }
    // And the total must be the number of cases in those files.
    assert!(out.contains("total: 190 passed, 0 failed"), "{out}");
}

#[test]
fn vectors_check_fails_loudly_when_an_expectation_is_wrong() {
    // Negative control: copy the vectors, break one root, expect exit 1.
    let temp = std::env::temp_dir().join(format!("abb-vectors-{}", std::process::id()));
    copy_dir(&vectors_dir(), &temp).expect("copy vectors");
    let roots = temp.join("merkle").join("roots.json");
    let text = std::fs::read_to_string(&roots).expect("read roots");
    let broken = text.replacen("\"root_hash\": \"", "\"root_hash\": \"dead", 1);
    std::fs::write(&roots, broken).expect("write roots");

    let (code, out, _) = call(&["vectors", "check", "--dir", &temp.to_string_lossy()]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("failed"), "{out}");
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn canon_prints_hex_text_and_digest_consistently() {
    let temp = std::env::temp_dir().join(format!("abb-canon-{}.json", std::process::id()));
    // Keys deliberately out of order, with whitespace.
    std::fs::write(&temp, "{\n  \"b\": 2,\n  \"a\": 1\n}\n").expect("write input");
    let path = temp.to_string_lossy().into_owned();

    let (code, hex_out, _) = call(&["canon", &path]);
    assert_eq!(code, 0);
    let (_, text_out, _) = call(&["canon", &path, "--text"]);
    assert_eq!(text_out.trim(), "{\"a\":1,\"b\":2}");
    assert_eq!(hex_out.trim(), hex_lower(text_out.trim().as_bytes()));

    let (_, digest_out, _) = call(&["canon", &path, "--sha256"]);
    assert_eq!(digest_out.trim().len(), 64);
    let _ = std::fs::remove_file(&temp);
}

#[test]
fn canon_rejects_a_float_with_exit_1_and_names_the_rule() {
    let temp = std::env::temp_dir().join(format!("abb-float-{}.json", std::process::id()));
    std::fs::write(&temp, "{\"amount\": 1.5}").expect("write input");
    let (code, _, err) = call(&["canon", &temp.to_string_lossy()]);
    assert_eq!(code, 1);
    assert!(err.contains("FLOAT_NOT_ALLOWED"), "{err}");
    let _ = std::fs::remove_file(&temp);
}

#[test]
fn keygen_writes_a_key_without_ever_printing_it() {
    let dir = std::env::temp_dir().join(format!("abb-keys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let dir_arg = dir.to_string_lossy().into_owned();

    let (code, out, err) = call(&["keygen", "--out", &dir_arg, "--role", "signer"]);
    assert_eq!(code, 0, "{err}");

    let private = std::fs::read(dir.join("signer.key")).expect("private key written");
    assert_eq!(private.len(), 32);
    let private_hex = hex_lower(&private);
    // The key must appear nowhere in what the user sees.
    assert!(!out.contains(&private_hex), "the private key was printed");
    assert!(
        !err.contains(&private_hex),
        "the private key was printed to stderr"
    );
    assert!(!out.to_lowercase().contains("begin"), "{out}");

    // The public half and the key id must be printed and must agree.
    let public_hex = std::fs::read_to_string(dir.join("signer.pub")).expect("public key written");
    let public_hex = public_hex.trim();
    assert!(out.contains(public_hex), "{out}");
    let expected_id = {
        let raw = abb_jcs::hex_decode(public_hex).expect("hex");
        let bytes: [u8; 32] = raw.try_into().expect("32 bytes");
        abb_checkpoint::key_id_for(&bytes)
    };
    assert!(out.contains(&expected_id), "{out}");

    // A second run must refuse rather than overwrite.
    let (code, _, err) = call(&["keygen", "--out", &dir_arg, "--role", "signer"]);
    assert_eq!(code, 64);
    assert!(err.contains("refusing to overwrite"), "{err}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Build a global log file with `count` runs, plus a signed global checkpoint.
fn global_log_file(dir: &Path, keep: &[usize], total: usize, name: &str) -> PathBuf {
    let signing = {
        use sha2::Digest as _;
        let seed: [u8; 32] = sha2::Sha256::digest(b"abb/1 test key v1 signer").into();
        ed25519_dalek::SigningKey::from_bytes(&seed)
    };

    let records: Vec<Vec<u8>> = (0..total)
        .map(|i| {
            let record = Value::Object(vec![
                (
                    "run_id".to_owned(),
                    Value::Str(format!("00000000-0000-4000-8000-00000000000{}", i + 1)),
                ),
                (
                    "checkpoint_hash".to_owned(),
                    Value::Str(hex_lower(&[(i + 1) as u8; 32])),
                ),
                ("tree_size".to_owned(), Value::Int(4 + i as i64)),
                (
                    "root_hash".to_owned(),
                    Value::Str(hex_lower(&[(i + 50) as u8; 32])),
                ),
                (
                    "manifest_head".to_owned(),
                    Value::Str(ZERO_HASH_HEX.to_owned()),
                ),
                (
                    "finalized_at".to_owned(),
                    Value::Int(1_760_000_000_000 + i as i64),
                ),
            ]);
            abb_jcs::canonical_bytes(&record).expect("canonical record")
        })
        .collect();

    // The checkpoint always covers all `total` runs: that is the signed truth.
    let all_leaves: Vec<Vec<u8>> = records
        .iter()
        .map(|r| tagged_bytes(tags::RUNROOT, r))
        .collect();
    let payload = CheckpointPayload {
        protocol_version: "abb/1".to_owned(),
        stream_id: "global".to_owned(),
        tree_size: total as i64,
        root_hash: hex_lower(&merkle::mth(&all_leaves)),
        manifest_size: 0,
        manifest_head: ZERO_HASH_HEX.to_owned(),
        prev_checkpoint_hash: ZERO_HASH_HEX.to_owned(),
        key_id: abb_checkpoint::key_id_for(&signing.verifying_key().to_bytes()),
        created_at: 1_760_000_500_000,
    };
    let signature = payload.sign(&signing).expect("sign");
    let canonical = payload.canonical_bytes().expect("canonical checkpoint");

    // The log file holds only the runs still present.
    let kept: Vec<Value> = keep
        .iter()
        .map(|i| {
            Value::Object(vec![(
                "record_canonical_b64".to_owned(),
                Value::Str(abb_cli::b64::encode(&records[*i])),
            )])
        })
        .collect();
    let doc = Value::Object(vec![
        ("records".to_owned(), Value::Array(kept)),
        (
            "global_checkpoint".to_owned(),
            Value::Object(vec![
                (
                    "canonical_b64".to_owned(),
                    Value::Str(abb_cli::b64::encode(&canonical)),
                ),
                ("signature".to_owned(), Value::Str(signature)),
            ]),
        ),
    ]);
    // Written with relaxed limits: this is a tooling file, not one event.
    let text = abb_jcs::to_canonical_with(&doc, &abb_jcs::Limits::relaxed()).expect("doc");
    let path = dir.join(name);
    std::fs::write(&path, text).expect("write log");
    path
}

#[test]
fn verify_global_accepts_an_intact_log_and_catches_a_deleted_run() {
    let dir = std::env::temp_dir().join(format!("abb-global-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let keys = vectors_dir()
        .join("keys")
        .join("test_keys.json")
        .to_string_lossy()
        .into_owned();

    // All five runs present: the recomputed root matches the signed checkpoint.
    let intact = global_log_file(&dir, &[0, 1, 2, 3, 4], 5, "intact.json");
    let (code, out, err) = call(&[
        "verify-global",
        "--roots",
        &intact.to_string_lossy(),
        "--keys",
        &keys,
    ]);
    assert_eq!(code, 0, "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("runs_in_log=5"), "{out}");
    assert!(out.contains("checkpoint_signature=PASS"), "{out}");
    assert!(out.contains("result=OK"), "{out}");
    // Without an anchor the tool must say the rollback question is unanswered.
    assert!(out.contains("anchor=UNKNOWN"), "{out}");

    // Run 3 deleted: the root no longer matches and a run is missing (TS-11).
    let deleted = global_log_file(&dir, &[0, 1, 3, 4], 5, "deleted.json");
    let (code, out, _) = call(&[
        "verify-global",
        "--roots",
        &deleted.to_string_lossy(),
        "--keys",
        &keys,
    ]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("runs_in_log=4"), "{out}");
    assert!(out.contains("GLOBAL_ROOT_MISMATCH"), "{out}");
    assert!(out.contains("MISSING_RUNS"), "{out}");
    assert!(out.contains("1 run(s) are gone"), "{out}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_global_reports_an_anchor_mismatch() {
    let dir = std::env::temp_dir().join(format!("abb-anchor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let log = global_log_file(&dir, &[0, 1, 2], 3, "log.json");

    // An anchor that published a different checkpoint hash for a larger tree.
    let anchor = dir.join("global.log");
    std::fs::write(
        &anchor,
        "# tree_size checkpoint_hash published_at\n5 ".to_owned()
            + &"ab".repeat(32)
            + " 1760000600000\n",
    )
    .expect("anchor");

    let (code, out, _) = call(&[
        "verify-global",
        "--roots",
        &log.to_string_lossy(),
        "--anchor",
        &anchor.to_string_lossy(),
    ]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("ANCHOR_MISMATCH"), "{out}");
    assert!(out.contains("MISSING_RUNS"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn verify_global_without_keys_does_not_claim_the_signature_passed() {
    let dir = std::env::temp_dir().join(format!("abb-nokeys-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let log = global_log_file(&dir, &[0, 1], 2, "log.json");
    let (code, out, _) = call(&["verify-global", "--roots", &log.to_string_lossy()]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("checkpoint_signature=UNKNOWN"), "{out}");
    assert!(!out.contains("checkpoint_signature=PASS"), "{out}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn attest_signs_the_request_and_never_prints_the_key() {
    // `abb attest` is on the production path: the ingestion service calls it
    // for every signing request (D-20). So it gets the same treatment as
    // keygen: the signature must verify, and the key must not leak.
    let dir = std::env::temp_dir().join(format!("abb-attest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    let keys = dir.join("keys");
    let (code, _, err) = call(&[
        "keygen",
        "--out",
        &keys.to_string_lossy(),
        "--role",
        "approver",
    ]);
    assert_eq!(code, 0, "{err}");
    let key_path = keys.join("approver.key");
    let public_hex = std::fs::read_to_string(keys.join("approver.pub")).expect("public key");
    let public_hex = public_hex.trim();

    // A minimal signing request, deliberately not in canonical key order.
    let request = dir.join("request.json");
    std::fs::write(
        &request,
        br#"{"stream_id":"run-1","append":{"from_sequence":0,"events":["e30="]}}"#,
    )
    .expect("write request");

    let (code, out, err) = call(&[
        "attest",
        "--key",
        &key_path.to_string_lossy(),
        "--file",
        &request.to_string_lossy(),
    ]);
    assert_eq!(code, 0, "{err}");

    let fields: std::collections::BTreeMap<&str, &str> = out
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let signature = fields.get("signature").expect("a signature");
    let body_hex = fields.get("body_hex").expect("a body");

    // The key never appears in what the command prints.
    let seed_hex = hex_lower(&std::fs::read(&key_path).expect("read key"));
    assert!(!out.contains(&seed_hex), "the private key was printed");
    assert!(!err.contains(&seed_hex));

    // The body is canonical, carries the attestation, and the signature
    // verifies over the request *without* it.
    let body = abb_jcs::hex_decode(body_hex).expect("hex body");
    let text = std::str::from_utf8(&body).expect("utf8");
    assert!(
        abb_jcs::is_canonical(text),
        "the body must be canonical: {text}"
    );
    let parsed = abb_jcs::parse_str(text, &abb_jcs::Limits::relaxed()).expect("parses");
    assert_eq!(
        parsed.get("caller_attestation").and_then(Value::as_str),
        Some(*signature)
    );

    let signing_bytes = abb_signer::request_signing_bytes(&parsed).expect("signing bytes");
    assert!(signing_bytes.starts_with(b"ABB1-SIGNREQ\0"));
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(
        &abb_jcs::hex_decode(public_hex)
            .expect("hex key")
            .try_into()
            .expect("32 bytes"),
    )
    .expect("a valid key");
    let raw: [u8; 64] = abb_jcs::hex_decode(signature)
        .expect("hex signature")
        .try_into()
        .expect("64 bytes");
    verifying
        .verify_strict(&signing_bytes, &ed25519_dalek::Signature::from_bytes(&raw))
        .expect("the attestation verifies");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn attest_needs_a_key_and_an_input() {
    let (code, _, err) = call(&["attest"]);
    assert_eq!(code, 64);
    assert!(err.contains("--key"), "{err}");

    let (code, _, err) = call(&["attest", "--key", "no-such-file"]);
    assert_eq!(code, 64, "{err}");
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
