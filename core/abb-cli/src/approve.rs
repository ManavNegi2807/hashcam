//! The approver's side (`PROTOCOL.md` 5.6, `D-16`), the mandate issuer's side
//! (5.7) and the field-commitment helper (5.5).
//!
//! `abb approve` is meant to run on the *approver's own device* with a key the
//! control plane never sees. It prints the signed statement; a person, or a
//! script they run, hands that to the service, which relays it. The service
//! never holds this key.
//!
//! A signature shows that a key signed. It does not show which person held
//! the key (`R-APR-08`).

use std::io::Write;
use std::path::Path;

use abb_checkpoint::{
    field_commitment, key_id_for, ApprovalStatement, KeyManifest, Mandate, Role, SALT_LEN,
};
use abb_jcs::{b64, hex_decode, hex_lower, Limits};
use ed25519_dalek::SigningKey;
use sha2::Digest as _;

use crate::{read_file, unreadable, usage, Args, CmdResult, EXIT_INVALID, EXIT_OK};

fn read_key(path: &str) -> Result<SigningKey, (i32, String)> {
    crate::witness::read_signing_key(Path::new(path)).map_err(unreadable)
}

fn need<'a>(args: &'a Args, command: &str, name: &str) -> Result<&'a str, (i32, String)> {
    args.flag(name)
        .ok_or_else(|| usage(format!("{command} needs --{name}")))
}

/// `abb approve`: sign a decision on one action.
pub(crate) fn cmd_approve(args: &Args, out: &mut impl Write, err: &mut impl Write) -> CmdResult {
    let key = read_key(need(args, "abb approve", "key")?)?;
    let decision = need(args, "abb approve", "decision")?;
    if decision != "GRANTED" && decision != "DENIED" {
        return Err(usage("--decision must be GRANTED or DENIED"));
    }
    let expires_at: i64 = need(args, "abb approve", "expires-at")?
        .parse()
        .map_err(|_| usage("--expires-at needs integer Unix milliseconds"))?;

    // The approver should sign what they actually read. With --summary the
    // digest is computed from the text that is shown right here.
    let summary_digest = match (args.flag("summary"), args.flag("summary-digest")) {
        (Some(text), None) => {
            let _ = writeln!(err, "You are signing a decision on exactly this:\n  {text}");
            hex_lower(&sha2::Sha256::digest(text.as_bytes()))
        }
        (None, Some(digest)) => digest.to_owned(),
        (Some(text), Some(digest)) => {
            let computed = hex_lower(&sha2::Sha256::digest(text.as_bytes()));
            if computed != digest {
                return Err((
                    EXIT_INVALID,
                    "APPROVAL_MISMATCH: the summary text does not hash to the digest in the \
                     request; refusing to sign something other than what was requested"
                        .to_owned(),
                ));
            }
            computed
        }
        (None, None) => return Err(usage("give --summary <text> or --summary-digest <hex>")),
    };

    let statement = ApprovalStatement {
        approval_id: need(args, "abb approve", "approval-id")?.to_owned(),
        run_id: need(args, "abb approve", "run-id")?.to_owned(),
        action_id: need(args, "abb approve", "action-id")?.to_owned(),
        summary_digest,
        decision: decision.to_owned(),
        expires_at,
    };
    // Round-trip through the strict reader so a statement we emit is one the
    // verifier will accept.
    let canonical = abb_jcs::to_canonical(&statement.to_value())
        .map_err(|e| (EXIT_INVALID, format!("cannot encode the statement: {e}")))?;
    ApprovalStatement::from_canonical(&canonical)
        .map_err(|e| (EXIT_INVALID, format!("not a valid approval: {e}")))?;
    let signature = statement
        .sign(&key)
        .map_err(|e| (EXIT_INVALID, format!("cannot sign: {e}")))?;

    let _ = writeln!(
        out,
        "key_id={}",
        key_id_for(&key.verifying_key().to_bytes())
    );
    let _ = writeln!(out, "statement_b64={}", b64::encode(canonical.as_bytes()));
    let _ = writeln!(out, "signature={signature}");
    Ok(EXIT_OK)
}

/// `abb approval check`: what the relaying service runs before it commits an
/// approval event. It checks the signature and the manifest role; the service
/// then compares action, summary and expiry with its own records.
pub(crate) fn cmd_approval(args: &Args, out: &mut impl Write) -> CmdResult {
    if args.word(1) != Some("check") {
        return Err(usage("abb approval needs the subcommand check"));
    }
    let manifest_bytes = read_file(need(args, "abb approval check", "keys")?)?;
    let manifest = abb_jcs::parse_bytes(&manifest_bytes, &Limits::relaxed())
        .map_err(|e| unreadable(format!("key manifest: {e}")))
        .and_then(|v| {
            KeyManifest::from_value(&v).map_err(|e| unreadable(format!("key manifest: {e}")))
        })?;
    let key_id = need(args, "abb approval check", "key-id")?;
    let bytes = b64::decode(need(args, "abb approval check", "statement-b64")?)
        .map_err(|_| usage("--statement-b64 is not base64"))?;
    let signature = need(args, "abb approval check", "signature")?;

    let text = std::str::from_utf8(&bytes).map_err(|_| {
        (
            EXIT_INVALID,
            "VALIDATION_FAILED: statement is not text".to_owned(),
        )
    })?;
    let statement = ApprovalStatement::from_canonical(text)
        .map_err(|e| (EXIT_INVALID, format!("VALIDATION_FAILED: {e}")))?;
    let entry = manifest
        .require(key_id, Role::Approver)
        .map_err(|e| (EXIT_INVALID, format!("UNKNOWN_APPROVER: {e}")))?;
    let key = entry
        .verifying_key()
        .map_err(|e| (EXIT_INVALID, format!("UNKNOWN_APPROVER: {e}")))?;
    statement
        .verify(signature, &key)
        .map_err(|_| (EXIT_INVALID, "BAD_SIGNATURE".to_owned()))?;

    let _ = writeln!(out, "approval_id={}", statement.approval_id);
    let _ = writeln!(out, "run_id={}", statement.run_id);
    let _ = writeln!(out, "action_id={}", statement.action_id);
    let _ = writeln!(out, "summary_digest={}", statement.summary_digest);
    let _ = writeln!(out, "decision={}", statement.decision);
    let _ = writeln!(out, "expires_at={}", statement.expires_at);
    Ok(EXIT_OK)
}

/// `abb mandate sign`: the issuer signs a mandate document.
pub(crate) fn cmd_mandate(args: &Args, out: &mut impl Write) -> CmdResult {
    match args.word(1) {
        Some("sign") => mandate_sign(args, out),
        Some("check") => mandate_check(args, out),
        _ => Err(usage("abb mandate needs the subcommand sign or check")),
    }
}

/// `abb mandate check`: verify a mandate's signature against the key manifest.
fn mandate_check(args: &Args, out: &mut impl Write) -> CmdResult {
    let manifest_bytes = read_file(need(args, "abb mandate check", "keys")?)?;
    let manifest = abb_jcs::parse_bytes(&manifest_bytes, &Limits::relaxed())
        .map_err(|e| unreadable(format!("key manifest: {e}")))
        .and_then(|v| {
            KeyManifest::from_value(&v).map_err(|e| unreadable(format!("key manifest: {e}")))
        })?;
    let bytes = b64::decode(need(args, "abb mandate check", "document-b64")?)
        .map_err(|_| usage("--document-b64 is not base64"))?;
    let signature = need(args, "abb mandate check", "signature")?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        (
            EXIT_INVALID,
            "VALIDATION_FAILED: mandate is not text".to_owned(),
        )
    })?;
    let mandate = Mandate::from_canonical(text)
        .map_err(|e| (EXIT_INVALID, format!("VALIDATION_FAILED: {e}")))?;
    let entry = manifest
        .require(&mandate.issuer_key_id, Role::MandateIssuer)
        .map_err(|e| (EXIT_INVALID, format!("UNKNOWN_ISSUER: {e}")))?;
    let key = entry
        .verifying_key()
        .map_err(|e| (EXIT_INVALID, format!("UNKNOWN_ISSUER: {e}")))?;
    mandate
        .verify(signature, &key)
        .map_err(|_| (EXIT_INVALID, "BAD_SIGNATURE".to_owned()))?;
    let digest = mandate
        .digest_hex()
        .map_err(|e| (EXIT_INVALID, format!("cannot digest: {e}")))?;
    let _ = writeln!(out, "mandate_id={}", mandate.mandate_id);
    let _ = writeln!(out, "mandate_digest={digest}");
    let _ = writeln!(out, "issuer_key_id={}", mandate.issuer_key_id);
    let _ = writeln!(out, "subject={}", mandate.subject);
    Ok(EXIT_OK)
}

fn mandate_sign(args: &Args, out: &mut impl Write) -> CmdResult {
    let key = read_key(need(args, "abb mandate sign", "key")?)?;
    let bytes = read_file(need(args, "abb mandate sign", "file")?)?;
    let value = abb_jcs::parse_bytes(&bytes, &Limits::relaxed())
        .map_err(|e| unreadable(format!("mandate file: {e}")))?;
    let canonical = abb_jcs::to_canonical(&value)
        .map_err(|e| (EXIT_INVALID, format!("mandate is not canonicalizable: {e}")))?;
    let mandate = Mandate::from_canonical(&canonical)
        .map_err(|e| (EXIT_INVALID, format!("not a valid mandate: {e}")))?;
    let own_id = key_id_for(&key.verifying_key().to_bytes());
    if mandate.issuer_key_id != own_id {
        return Err((
            EXIT_INVALID,
            "the mandate names a different issuer than the key you are signing with".to_owned(),
        ));
    }
    let signature = mandate
        .sign(&key)
        .map_err(|e| (EXIT_INVALID, format!("cannot sign: {e}")))?;
    let digest = mandate
        .digest_hex()
        .map_err(|e| (EXIT_INVALID, format!("cannot digest: {e}")))?;
    let _ = writeln!(out, "mandate_digest={digest}");
    let _ = writeln!(out, "issuer_key_id={own_id}");
    let _ = writeln!(out, "document_b64={}", b64::encode(canonical.as_bytes()));
    let _ = writeln!(out, "signature={signature}");
    Ok(EXIT_OK)
}

/// `abb commit`: make a salted commitment to one value (`PROTOCOL.md` 5.5).
///
/// With no `--salt-hex` a fresh 16-byte salt comes from the operating system's
/// CSPRNG. The caller stores the salt and value in the secret store and puts
/// only the commitment in the event.
pub(crate) fn cmd_commit(args: &Args, out: &mut impl Write) -> CmdResult {
    // --stdin keeps a secret value out of the process list.
    let value_text = if args.present("stdin") {
        let mut buffer = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut buffer)
            .map_err(|e| unreadable(format!("cannot read stdin: {e}")))?;
        buffer
    } else {
        need(args, "abb commit", "value-json")?.to_owned()
    };
    let value = abb_jcs::parse(value_text.trim()).map_err(|e| usage(format!("value: {e}")))?;
    let salt: Vec<u8> = match args.flag("salt-hex") {
        Some(text) => {
            let salt = hex_decode(text).map_err(|_| usage("--salt-hex is not hex"))?;
            if salt.len() != SALT_LEN {
                return Err(usage("a salt must be exactly 16 bytes"));
            }
            salt
        }
        None => {
            let mut fresh = [0u8; SALT_LEN];
            getrandom::fill(&mut fresh)
                .map_err(|e| (70, format!("no secure randomness available: {e}")))?;
            fresh.to_vec()
        }
    };
    let commitment = field_commitment(&salt, &value)
        .map_err(|e| (EXIT_INVALID, format!("cannot commit: {e}")))?;
    let _ = writeln!(out, "salt_hex={}", hex_lower(&salt));
    let _ = writeln!(out, "commitment={commitment}");
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> (i32, String, String) {
        let raw: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = crate::run(&raw, &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn field(out: &str, name: &str) -> String {
        out.lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .unwrap_or_default()
            .to_owned()
    }

    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("abb-approve-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A manifest listing the approver key, built from keygen's output.
    fn approver_setup(label: &str) -> (std::path::PathBuf, String) {
        let dir = scratch(label);
        let (code, out, _) = run(&[
            "keygen",
            "--out",
            dir.to_str().unwrap(),
            "--role",
            "approver",
        ]);
        assert_eq!(code, 0);
        let key_id = field(&out, "key_id");
        let manifest = format!(
            r#"{{"keys":[{{"key_id":"{key_id}","public_key_hex":"{}","role":"approver","valid_from":1,"status":"active"}}]}}"#,
            field(&out, "public_key_hex")
        );
        std::fs::write(dir.join("manifest.json"), manifest).unwrap();
        (dir, key_id)
    }

    const RUN: &str = "11111111-1111-4111-8111-111111111111";

    fn sign(dir: &Path, decision: &str, extra: &[&str]) -> (i32, String, String) {
        let key = dir.join("approver.key");
        let mut args = vec![
            "approve",
            "--key",
            key.to_str().unwrap(),
            "--run-id",
            RUN,
            "--action-id",
            "a1",
            "--approval-id",
            "ap1",
            "--decision",
            decision,
            "--expires-at",
            "5000",
        ];
        args.extend_from_slice(extra);
        run(&args)
    }

    #[test]
    fn what_the_approver_signs_the_service_can_check() {
        let (dir, key_id) = approver_setup("roundtrip");
        let (code, out, err) = sign(
            &dir,
            "GRANTED",
            &["--summary", "CLICK https://vendor.example/x"],
        );
        assert_eq!(code, 0, "{err}");
        // The approver is shown exactly what they sign.
        assert!(err.contains("CLICK https://vendor.example/x"));
        assert_eq!(field(&out, "key_id"), key_id);

        let (code, checked, err) = run(&[
            "approval",
            "check",
            "--keys",
            dir.join("manifest.json").to_str().unwrap(),
            "--key-id",
            &key_id,
            "--statement-b64",
            &field(&out, "statement_b64"),
            "--signature",
            &field(&out, "signature"),
        ]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(field(&checked, "decision"), "GRANTED");
        assert_eq!(field(&checked, "action_id"), "a1");
        assert_eq!(field(&checked, "expires_at"), "5000");
    }

    #[test]
    fn a_summary_that_does_not_hash_to_the_request_is_not_signed() {
        let (dir, _) = approver_setup("mismatch");
        let (code, out, err) = sign(
            &dir,
            "GRANTED",
            &[
                "--summary",
                "CLICK https://evil.test/x",
                "--summary-digest",
                &"ab".repeat(32),
            ],
        );
        assert_eq!(code, 1);
        assert!(err.contains("APPROVAL_MISMATCH"), "{err}");
        assert!(!out.contains("signature="));
    }

    #[test]
    fn a_tampered_statement_or_signature_fails_the_check() {
        let (dir, key_id) = approver_setup("tamper");
        let (_, out, _) = sign(&dir, "GRANTED", &["--summary-digest", &"ab".repeat(32)]);
        let manifest = dir.join("manifest.json");
        let check = |statement: &str, signature: &str| {
            run(&[
                "approval",
                "check",
                "--keys",
                manifest.to_str().unwrap(),
                "--key-id",
                &key_id,
                "--statement-b64",
                statement,
                "--signature",
                signature,
            ])
        };
        // Change the decision inside the statement.
        let bytes = b64::decode(&field(&out, "statement_b64")).unwrap();
        let forged = String::from_utf8(bytes)
            .unwrap()
            .replace("GRANTED", "DENIED");
        let (code, _, err) = check(&b64::encode(forged.as_bytes()), &field(&out, "signature"));
        assert_eq!(code, 1);
        assert!(err.contains("BAD_SIGNATURE"), "{err}");
        // A flipped signature bit.
        let mut sig = field(&out, "signature").into_bytes();
        sig[0] = if sig[0] == b'0' { b'1' } else { b'0' };
        let (code, _, _) = check(
            &field(&out, "statement_b64"),
            std::str::from_utf8(&sig).unwrap(),
        );
        assert_eq!(code, 1);
    }

    #[test]
    fn a_key_that_is_not_an_approver_in_the_manifest_is_refused() {
        let (dir, _) = approver_setup("role");
        let other = scratch("role-other");
        let (_, o, _) = run(&[
            "keygen",
            "--out",
            other.to_str().unwrap(),
            "--role",
            "approver",
        ]);
        let stranger = field(&o, "key_id");
        let (_, out, _) = sign(&dir, "GRANTED", &["--summary-digest", &"ab".repeat(32)]);
        let (code, _, err) = run(&[
            "approval",
            "check",
            "--keys",
            dir.join("manifest.json").to_str().unwrap(),
            "--key-id",
            &stranger,
            "--statement-b64",
            &field(&out, "statement_b64"),
            "--signature",
            &field(&out, "signature"),
        ]);
        assert_eq!(code, 1);
        assert!(err.contains("UNKNOWN_APPROVER"), "{err}");
    }

    #[test]
    fn the_decision_must_be_granted_or_denied() {
        let (dir, _) = approver_setup("decision");
        let (code, _, _) = sign(&dir, "MAYBE", &["--summary-digest", &"ab".repeat(32)]);
        assert_eq!(code, 64);
    }

    #[test]
    fn no_private_key_bytes_appear_in_any_output() {
        let (dir, _) = approver_setup("noleak");
        let seed = std::fs::read(dir.join("approver.key")).unwrap();
        let (_, out, err) = sign(&dir, "GRANTED", &["--summary", "x"]);
        for text in [&out, &err] {
            assert!(!text.contains(&hex_lower(&seed)));
            assert!(!text.contains(&b64::encode(&seed)));
        }
    }

    #[test]
    fn a_mandate_is_signed_only_by_its_named_issuer() {
        let dir = scratch("mandate");
        let (_, out, _) = run(&[
            "keygen",
            "--out",
            dir.to_str().unwrap(),
            "--role",
            "mandate_issuer",
        ]);
        let id = field(&out, "key_id");
        let doc = format!(
            r#"{{"mandate_id":"m1","issuer_key_id":"{id}","subject":"replay","allowed_hosts":["vendor.example"],"allowed_action_types":["CLICK"],"max_actions":3,"not_before":1,"not_after":99}}"#
        );
        std::fs::write(dir.join("mandate.json"), &doc).unwrap();
        let (code, signed, err) = run(&[
            "mandate",
            "sign",
            "--key",
            dir.join("mandate_issuer.key").to_str().unwrap(),
            "--file",
            dir.join("mandate.json").to_str().unwrap(),
        ]);
        assert_eq!(code, 0, "{err}");
        assert_eq!(field(&signed, "mandate_digest").len(), 64);
        assert_eq!(field(&signed, "issuer_key_id"), id);

        // Someone else's key cannot sign a mandate that names this issuer.
        let other = scratch("mandate-other");
        run(&[
            "keygen",
            "--out",
            other.to_str().unwrap(),
            "--role",
            "mandate_issuer",
        ]);
        let (code, _, err) = run(&[
            "mandate",
            "sign",
            "--key",
            other.join("mandate_issuer.key").to_str().unwrap(),
            "--file",
            dir.join("mandate.json").to_str().unwrap(),
        ]);
        assert_eq!(code, 1);
        assert!(err.contains("different issuer"), "{err}");
    }

    #[test]
    fn a_signed_mandate_checks_against_the_manifest_and_a_forgery_does_not() {
        let dir = scratch("mandate-check");
        let (_, out, _) = run(&[
            "keygen",
            "--out",
            dir.to_str().unwrap(),
            "--role",
            "mandate_issuer",
        ]);
        let id = field(&out, "key_id");
        let manifest = format!(
            r#"{{"keys":[{{"key_id":"{id}","public_key_hex":"{}","role":"mandate_issuer","valid_from":1,"status":"active"}}]}}"#,
            field(&out, "public_key_hex")
        );
        std::fs::write(dir.join("manifest.json"), manifest).unwrap();
        let doc = format!(
            r#"{{"mandate_id":"m1","issuer_key_id":"{id}","subject":"replay","allowed_hosts":["vendor.example"],"allowed_action_types":["CLICK"],"max_actions":3,"not_before":1,"not_after":99}}"#
        );
        std::fs::write(dir.join("mandate.json"), doc).unwrap();
        let (_, signed, _) = run(&[
            "mandate",
            "sign",
            "--key",
            dir.join("mandate_issuer.key").to_str().unwrap(),
            "--file",
            dir.join("mandate.json").to_str().unwrap(),
        ]);
        let check = |document: &str, signature: &str| {
            run(&[
                "mandate",
                "check",
                "--keys",
                dir.join("manifest.json").to_str().unwrap(),
                "--document-b64",
                document,
                "--signature",
                signature,
            ])
        };
        let (code, ok, err) = check(
            &field(&signed, "document_b64"),
            &field(&signed, "signature"),
        );
        assert_eq!(code, 0, "{err}");
        assert_eq!(
            field(&ok, "mandate_digest"),
            field(&signed, "mandate_digest")
        );

        let loosened = String::from_utf8(b64::decode(&field(&signed, "document_b64")).unwrap())
            .unwrap()
            .replace("\"max_actions\":3", "\"max_actions\":300");
        let (code, _, err) = check(
            &b64::encode(loosened.as_bytes()),
            &field(&signed, "signature"),
        );
        assert_eq!(code, 1);
        assert!(err.contains("BAD_SIGNATURE"), "{err}");
    }

    #[test]
    fn commit_uses_a_fresh_salt_each_time_and_reproduces_with_a_given_one() {
        let (c1, a, _) = run(&["commit", "--value-json", "\"4111111111111111\""]);
        let (c2, b, _) = run(&["commit", "--value-json", "\"4111111111111111\""]);
        assert_eq!((c1, c2), (0, 0));
        assert_ne!(field(&a, "salt_hex"), field(&b, "salt_hex"));
        assert_ne!(field(&a, "commitment"), field(&b, "commitment"));
        let (_, again, _) = run(&[
            "commit",
            "--value-json",
            "\"4111111111111111\"",
            "--salt-hex",
            &field(&a, "salt_hex"),
        ]);
        assert_eq!(field(&again, "commitment"), field(&a, "commitment"));
        assert_eq!(field(&a, "salt_hex").len(), 32);
    }

    #[test]
    fn commit_refuses_a_short_salt_and_a_float() {
        let (code, _, _) = run(&["commit", "--value-json", "1", "--salt-hex", "0102"]);
        assert_eq!(code, 64);
        let (code, _, _) = run(&["commit", "--value-json", "1.5"]);
        assert_eq!(code, 64);
    }
}
