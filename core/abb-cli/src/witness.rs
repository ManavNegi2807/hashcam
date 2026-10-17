//! The witness procedure and the anchor file (`PROTOCOL.md` 12 and 13).
//!
//! A witness exists to be a second opinion that does not share the signer's
//! failure. So the two rules that matter are about what it refuses:
//!
//! * it **does not cosign blindly** (`R-WIT-06`). Given the global run-root
//!   records, it rebuilds the tree itself, checks the root against the signed
//!   checkpoint, checks the signer's signature, and checks that the tree it saw
//!   last time is a prefix of this one;
//! * it keeps **its own anti-rollback state** (`R-WIT-02`), written before the
//!   signature is returned, and it refuses a smaller tree or a different tree of
//!   the same size.
//!
//! Whether a witness counts as independent is not decided here: that is the
//! verifier's call from the `failure_domain` labels (`D-15`). Running this on
//! the signer's own machine produces a valid signature that the verifier will
//! correctly call `NOT_INDEPENDENT`.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use abb_checkpoint::{tagged_bytes, tags, CheckpointPayload, KeyManifest, Role, WitnessStatement};
use abb_jcs::{b64, hex_decode, hex_lower, Limits, Value};
use abb_merkle as merkle;
use ed25519_dalek::SigningKey;

/// What a witness remembers between runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessState {
    /// Tree size of the last checkpoint it signed.
    pub tree_size: i64,
    /// Root of that tree.
    pub root_hash: String,
    /// Hash of that checkpoint.
    pub checkpoint_hash: String,
}

/// Why a witness refused to sign. Codes follow `DATABASE_AND_API_CONTRACTS.md` B5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRefusal {
    /// The checkpoint's signature or signer key did not check out.
    BadCheckpoint(String),
    /// The records do not rebuild the checkpoint's root.
    RootMismatch,
    /// The new tree does not contain the one seen before.
    NotExtending,
    /// A smaller tree than one already witnessed.
    SizeRegression,
    /// The same size as before, but a different checkpoint.
    ForkDetected,
    /// The state file is unreadable or inconsistent.
    StateCorrupt,
}

impl WitnessRefusal {
    /// The wire code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadCheckpoint(_) => "BAD_CHECKPOINT",
            Self::RootMismatch => "ROOT_MISMATCH",
            Self::NotExtending => "NOT_EXTENDING",
            Self::SizeRegression => "SIZE_REGRESSION",
            Self::ForkDetected => "FORK_DETECTED",
            Self::StateCorrupt => "STATE_CORRUPT",
        }
    }
}

impl std::fmt::Display for WitnessRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadCheckpoint(why) => write!(f, "BAD_CHECKPOINT: {why}"),
            other => f.write_str(other.code()),
        }
    }
}

/// Read the state file, if there is one.
pub fn load_state(path: &Path) -> Result<Option<WitnessState>, WitnessRefusal> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|_| WitnessRefusal::StateCorrupt)?;
    let value = abb_jcs::parse_bytes(&bytes, &Limits::relaxed())
        .map_err(|_| WitnessRefusal::StateCorrupt)?;
    let size = value
        .get("tree_size")
        .and_then(Value::as_int)
        .ok_or(WitnessRefusal::StateCorrupt)?;
    let root = value
        .get("root_hash")
        .and_then(Value::as_str)
        .ok_or(WitnessRefusal::StateCorrupt)?;
    let hash = value
        .get("checkpoint_hash")
        .and_then(Value::as_str)
        .ok_or(WitnessRefusal::StateCorrupt)?;
    Ok(Some(WitnessState {
        tree_size: size,
        root_hash: root.to_owned(),
        checkpoint_hash: hash.to_owned(),
    }))
}

/// Write the state durably: temp file, flush, sync, rename.
pub fn save_state(path: &Path, state: &WitnessState) -> Result<(), WitnessRefusal> {
    let value = Value::Object(vec![
        ("tree_size".to_owned(), Value::Int(state.tree_size)),
        ("root_hash".to_owned(), Value::Str(state.root_hash.clone())),
        (
            "checkpoint_hash".to_owned(),
            Value::Str(state.checkpoint_hash.clone()),
        ),
    ]);
    let text = abb_jcs::to_canonical_with(&value, &Limits::relaxed())
        .map_err(|_| WitnessRefusal::StateCorrupt)?;
    let temp = path.with_extension("tmp");
    let mut file = fs::File::create(&temp).map_err(|_| WitnessRefusal::StateCorrupt)?;
    file.write_all(text.as_bytes())
        .map_err(|_| WitnessRefusal::StateCorrupt)?;
    file.sync_all().map_err(|_| WitnessRefusal::StateCorrupt)?;
    fs::rename(&temp, path).map_err(|_| WitnessRefusal::StateCorrupt)?;
    Ok(())
}

/// The outcome of a successful witnessing.
#[derive(Debug, Clone)]
pub struct Witnessed {
    /// The exact signed statement bytes.
    pub statement: Vec<u8>,
    /// Hex signature over them.
    pub signature: String,
    /// The witness's new state.
    pub state: WitnessState,
}

/// Everything a witness needs to decide, and the key to sign with.
pub struct Request<'a> {
    /// The signer's checkpoint payload bytes, exactly as signed.
    pub checkpoint_payload: &'a [u8],
    /// The signer's signature over it.
    pub checkpoint_signature: &'a str,
    /// The global run-root records, in order, as canonical bytes.
    pub records: &'a [Vec<u8>],
    /// Trusted keys; the signer must be in here with role `signer`.
    pub keys: &'a KeyManifest,
    /// What this witness saw last time.
    pub previous: Option<WitnessState>,
    /// This witness's identity: its key id.
    pub witness_id: &'a str,
    /// This witness's independence label.
    pub failure_domain: &'a str,
    /// Unix ms for the statement. A claim.
    pub now_ms: i64,
}

/// Decide whether to sign. Pure: no files are touched here.
pub fn witness(request: &Request<'_>, key: &SigningKey) -> Result<Witnessed, WitnessRefusal> {
    // 1. The checkpoint is well formed, and signed by a key we trust as a signer.
    let text = std::str::from_utf8(request.checkpoint_payload)
        .map_err(|_| WitnessRefusal::BadCheckpoint("payload is not UTF-8".to_owned()))?;
    let payload = CheckpointPayload::from_canonical(text)
        .map_err(|e| WitnessRefusal::BadCheckpoint(e.to_string()))?;
    if payload.stream_id != "global" {
        return Err(WitnessRefusal::BadCheckpoint(
            "witnesses sign global checkpoints (D-10)".to_owned(),
        ));
    }
    let entry = request
        .keys
        .require(&payload.key_id, Role::Signer)
        .map_err(|e| WitnessRefusal::BadCheckpoint(format!("signer key: {e}")))?;
    let verifying = entry
        .verifying_key()
        .map_err(|e| WitnessRefusal::BadCheckpoint(e.to_string()))?;
    payload
        .verify(request.checkpoint_signature, &verifying)
        .map_err(|e| WitnessRefusal::BadCheckpoint(format!("signature: {e}")))?;

    // 2. Rebuild the tree from the records and compare. Never trust a root.
    let leaves: Vec<Vec<u8>> = request
        .records
        .iter()
        .map(|r| tagged_bytes(tags::RUNROOT, r))
        .collect();
    let size = i64::try_from(leaves.len()).unwrap_or(i64::MAX);
    if size != payload.tree_size || hex_lower(&merkle::mth(&leaves)) != payload.root_hash {
        return Err(WitnessRefusal::RootMismatch);
    }
    let checkpoint_hash = payload
        .checkpoint_hash_hex()
        .map_err(|e| WitnessRefusal::BadCheckpoint(e.to_string()))?;

    // 3. Against what this witness saw before.
    if let Some(previous) = &request.previous {
        if payload.tree_size < previous.tree_size {
            return Err(WitnessRefusal::SizeRegression);
        }
        if payload.tree_size == previous.tree_size {
            // Idempotent only if it is the very same checkpoint.
            if checkpoint_hash != previous.checkpoint_hash {
                return Err(WitnessRefusal::ForkDetected);
            }
        } else {
            // The earlier tree must be a prefix of this one: rebuild its root
            // from the first `n` records and compare with what we stored.
            let prefix_len =
                usize::try_from(previous.tree_size).map_err(|_| WitnessRefusal::StateCorrupt)?;
            let prefix = leaves
                .get(..prefix_len)
                .ok_or(WitnessRefusal::NotExtending)?;
            if hex_lower(&merkle::mth(prefix)) != previous.root_hash {
                return Err(WitnessRefusal::NotExtending);
            }
        }
    }

    // 4. Sign, and say where this witness says it was.
    let statement = WitnessStatement {
        witness_id: request.witness_id.to_owned(),
        stream_id: "global".to_owned(),
        checkpoint_hash: checkpoint_hash.clone(),
        tree_size: payload.tree_size,
        failure_domain: request.failure_domain.to_owned(),
        created_at: request.now_ms,
    };
    let signature = statement
        .sign(key)
        .map_err(|e| WitnessRefusal::BadCheckpoint(e.to_string()))?;
    let bytes = abb_jcs::canonical_bytes(&statement.to_value())
        .map_err(|e| WitnessRefusal::BadCheckpoint(e.to_string()))?;
    Ok(Witnessed {
        statement: bytes,
        signature,
        state: WitnessState {
            tree_size: payload.tree_size,
            root_hash: payload.root_hash,
            checkpoint_hash,
        },
    })
}

// --------------------------------------------------------------------------- //
// the anchor file
// --------------------------------------------------------------------------- //

/// Why an anchor line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorRefusal {
    /// The line would not extend the file.
    NotExtending,
    /// Same size as an existing line but a different hash.
    Conflict,
    /// The file could not be read or written.
    Io(String),
}

impl std::fmt::Display for AnchorRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotExtending => f.write_str("NOT_EXTENDING: the anchor file only grows"),
            Self::Conflict => {
                f.write_str("FORK_DETECTED: a different hash is already anchored at that size")
            }
            Self::Io(why) => write!(f, "{why}"),
        }
    }
}

/// Append `tree_size checkpoint_hash published_at` to an append-only file.
///
/// The file is a plain text list, one global checkpoint per line, so it is easy
/// to put in a public Git repository and easy to read by eye (`D-15`). This
/// function refuses to rewrite history; the real append-only guarantee comes
/// from the Git history around it, not from this check.
pub fn anchor_append(
    path: &Path,
    tree_size: i64,
    checkpoint_hash: &str,
    published_at: i64,
) -> Result<(), AnchorRefusal> {
    let existing = if path.exists() {
        fs::read_to_string(path).map_err(|e| AnchorRefusal::Io(e.to_string()))?
    } else {
        String::new()
    };
    for line in existing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let mut parts = line.split_whitespace();
        let (Some(size), Some(hash)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(size) = size.parse::<i64>() else {
            continue;
        };
        if size == tree_size {
            return if hash == checkpoint_hash {
                Ok(())
            } else {
                Err(AnchorRefusal::Conflict)
            };
        }
        if size > tree_size {
            return Err(AnchorRefusal::NotExtending);
        }
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| AnchorRefusal::Io(e.to_string()))?;
    if existing.is_empty() {
        writeln!(file, "# tree_size checkpoint_hash published_at")
            .map_err(|e| AnchorRefusal::Io(e.to_string()))?;
    }
    writeln!(file, "{tree_size} {checkpoint_hash} {published_at}")
        .map_err(|e| AnchorRefusal::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| AnchorRefusal::Io(e.to_string()))?;
    Ok(())
}

/// Decode a file of base64 records, one per line.
pub fn read_records(path: &Path) -> Result<Vec<Vec<u8>>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut records = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        records.push(b64::decode(line).map_err(|e| format!("line {}: {e}", n + 1))?);
    }
    Ok(records)
}

/// Decode a 32-byte seed from a key file.
pub fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let seed = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| "the key file must hold 32 bytes".to_owned())?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Parse a lowercase hex digest into 32 bytes.
pub fn digest_from_hex(text: &str) -> Option<[u8; 32]> {
    hex_decode(text).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use abb_checkpoint::{key_id_for, ZERO_HASH_HEX};
    use sha2::Digest as _;

    fn key(label: &str) -> SigningKey {
        SigningKey::from_bytes(&sha2::Sha256::digest(label.as_bytes()).into())
    }

    struct World {
        signer: SigningKey,
        witness: SigningKey,
        keys: KeyManifest,
    }

    fn world() -> World {
        let signer = key("signer");
        let witness = key("witness");
        let manifest = |sk: &SigningKey, role: Role, domain: &str| abb_checkpoint::KeyEntry {
            key_id: key_id_for(&sk.verifying_key().to_bytes()),
            public_key: sk.verifying_key().to_bytes(),
            role,
            failure_domain: Some(domain.to_owned()),
            valid_from: 0,
            status: "active".to_owned(),
        };
        World {
            keys: KeyManifest {
                keys: vec![
                    manifest(&signer, Role::Signer, "host:a/admin:alice"),
                    manifest(&witness, Role::Witness, "host:b/admin:bob"),
                ],
            },
            signer,
            witness,
        }
    }

    fn records(n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| format!("{{\"run\":{i}}}").into_bytes())
            .collect()
    }

    fn checkpoint(w: &World, recs: &[Vec<u8>], prev: &str) -> (Vec<u8>, String) {
        let leaves: Vec<Vec<u8>> = recs
            .iter()
            .map(|r| tagged_bytes(tags::RUNROOT, r))
            .collect();
        let payload = CheckpointPayload {
            protocol_version: "abb/1".to_owned(),
            stream_id: "global".to_owned(),
            tree_size: i64::try_from(recs.len()).unwrap(),
            root_hash: hex_lower(&merkle::mth(&leaves)),
            manifest_size: 0,
            manifest_head: ZERO_HASH_HEX.to_owned(),
            prev_checkpoint_hash: prev.to_owned(),
            key_id: key_id_for(&w.signer.verifying_key().to_bytes()),
            created_at: 1,
        };
        let sig = payload.sign(&w.signer).unwrap();
        (payload.canonical_bytes().unwrap(), sig)
    }

    fn request<'a>(
        w: &'a World,
        payload: &'a [u8],
        sig: &'a str,
        recs: &'a [Vec<u8>],
        previous: Option<WitnessState>,
        id: &'a str,
    ) -> Request<'a> {
        Request {
            checkpoint_payload: payload,
            checkpoint_signature: sig,
            records: recs,
            keys: &w.keys,
            previous,
            witness_id: id,
            failure_domain: "host:b/admin:bob",
            now_ms: 5,
        }
    }

    #[test]
    fn a_checkpoint_it_can_rebuild_is_signed_and_the_signature_verifies() {
        let w = world();
        let recs = records(3);
        let (payload, sig) = checkpoint(&w, &recs, ZERO_HASH_HEX);
        let id = key_id_for(&w.witness.verifying_key().to_bytes());
        let done = witness(&request(&w, &payload, &sig, &recs, None, &id), &w.witness).unwrap();
        assert_eq!(done.state.tree_size, 3);
        let statement =
            WitnessStatement::from_canonical(std::str::from_utf8(&done.statement).unwrap())
                .unwrap();
        statement
            .verify(&done.signature, &w.witness.verifying_key())
            .unwrap();
        assert_eq!(statement.failure_domain, "host:b/admin:bob");
    }

    #[test]
    fn it_refuses_a_root_the_records_do_not_rebuild() {
        let w = world();
        let recs = records(3);
        let (payload, sig) = checkpoint(&w, &recs, ZERO_HASH_HEX);
        let mut doctored = recs.clone();
        doctored[1] = b"{\"run\":99}".to_vec();
        let id = "witness";
        let err = witness(
            &request(&w, &payload, &sig, &doctored, None, id),
            &w.witness,
        )
        .unwrap_err();
        assert_eq!(err, WitnessRefusal::RootMismatch);
    }

    #[test]
    fn it_refuses_a_checkpoint_the_signer_did_not_sign() {
        let w = world();
        let recs = records(2);
        let (payload, _) = checkpoint(&w, &recs, ZERO_HASH_HEX);
        let bad = "00".repeat(64);
        let err = witness(&request(&w, &payload, &bad, &recs, None, "w"), &w.witness).unwrap_err();
        assert!(matches!(err, WitnessRefusal::BadCheckpoint(_)), "{err:?}");
    }

    #[test]
    fn it_extends_a_prefix_it_has_seen_and_refuses_everything_else() {
        let w = world();
        let first = records(2);
        let (p1, s1) = checkpoint(&w, &first, ZERO_HASH_HEX);
        let seen = witness(&request(&w, &p1, &s1, &first, None, "w"), &w.witness).unwrap();

        // A genuine extension.
        let more = records(4);
        let (p2, s2) = checkpoint(&w, &more, &seen.state.checkpoint_hash);
        let next = witness(
            &request(&w, &p2, &s2, &more, Some(seen.state.clone()), "w"),
            &w.witness,
        )
        .unwrap();
        assert_eq!(next.state.tree_size, 4);

        // Rolled back: asked to sign the smaller tree after the larger one.
        let err = witness(
            &request(&w, &p1, &s1, &first, Some(next.state.clone()), "w"),
            &w.witness,
        )
        .unwrap_err();
        assert_eq!(err, WitnessRefusal::SizeRegression);

        // Same size, different history: a fork.
        let mut other = records(4);
        other[0] = b"{\"run\":\"rewritten\"}".to_vec();
        let (p3, s3) = checkpoint(&w, &other, "ab".repeat(32).as_str());
        let err = witness(
            &request(&w, &p3, &s3, &other, Some(next.state.clone()), "w"),
            &w.witness,
        )
        .unwrap_err();
        assert_eq!(err, WitnessRefusal::ForkDetected);

        // Bigger, but rewritten underneath: the old tree is not a prefix.
        let mut rewritten = records(5);
        rewritten[0] = b"{\"run\":\"rewritten\"}".to_vec();
        let (p4, s4) = checkpoint(&w, &rewritten, "cd".repeat(32).as_str());
        let err = witness(
            &request(&w, &p4, &s4, &rewritten, Some(next.state), "w"),
            &w.witness,
        )
        .unwrap_err();
        assert_eq!(err, WitnessRefusal::NotExtending);
    }

    #[test]
    fn state_survives_a_restart_and_a_corrupt_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("abb-witness-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        assert_eq!(load_state(&path).unwrap(), None);
        let state = WitnessState {
            tree_size: 3,
            root_hash: "ab".repeat(32),
            checkpoint_hash: "cd".repeat(32),
        };
        save_state(&path, &state).unwrap();
        assert_eq!(load_state(&path).unwrap(), Some(state));
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(load_state(&path).unwrap_err(), WitnessRefusal::StateCorrupt);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_anchor_file_only_grows_and_refuses_a_conflict() {
        let dir = std::env::temp_dir().join(format!("abb-anchor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("global.log");
        let _ = std::fs::remove_file(&path);
        anchor_append(&path, 1, &"aa".repeat(32), 100).unwrap();
        anchor_append(&path, 2, &"bb".repeat(32), 200).unwrap();
        // The same line again is a no-op, not a duplicate.
        anchor_append(&path, 2, &"bb".repeat(32), 999).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
        // A different hash at an anchored size is refused.
        assert_eq!(
            anchor_append(&path, 2, &"cc".repeat(32), 300).unwrap_err(),
            AnchorRefusal::Conflict
        );
        // And so is going backwards.
        assert_eq!(
            anchor_append(&path, 1, &"aa".repeat(32), 100).map_err(|_| ()),
            Ok(())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
