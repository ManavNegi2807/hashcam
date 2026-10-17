//! The signer's own state: a hash-chained, append-only log on its own volume.
//!
//! `PROTOCOL.md` 11.3 and `R-SIG-09`, `R-SIG-10`, `R-SIG-12`:
//!
//! * one line per signed checkpoint, each carrying the hash of the line before
//!   it, so a later edit cannot pass unnoticed;
//! * written and `fsync`ed **before** a signature is returned;
//! * on a broken chain the signer **fails closed** and refuses to sign until an
//!   operator intervenes. It never silently resets.
//!
//! The log is also the signer's answer to "did I sign this checkpoint?", which
//! is what lets it refuse a run root nobody asked it to append (`R-GLB-02`).
//!
//! This state is internal. Nothing here goes into a receipt, so the entry hash
//! needs no protocol domain tag and the layout can change without touching
//! `protocol_version`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use abb_checkpoint::{CheckpointPayload, ZERO_HASH_HEX};
use abb_jcs::{b64, hex_decode, hex_lower, Limits, Value};
use abb_merkle::{Frontier, Hash};
use sha2::{Digest, Sha256};

use crate::{SignerError, StoredCheckpoint};

/// What the signer knows about one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamState {
    /// Number of leaves covered by the last checkpoint.
    pub tree_size: i64,
    /// Root of those leaves.
    pub root_hash: String,
    /// Hash of the last checkpoint this signer produced for the stream.
    pub checkpoint_hash: String,
    /// Entries in the artifact manifest at that checkpoint.
    pub manifest_size: i64,
    /// Manifest head at that checkpoint.
    pub manifest_head: String,
    /// True once `RUN_FINISHED` has been signed for this stream.
    pub finished: bool,
    /// The O(log n) hashes needed to extend the tree without replaying it.
    pub frontier: Frontier,
    /// The last checkpoint itself, returned verbatim on an idempotent replay.
    pub checkpoint: StoredCheckpoint,
}

/// The in-memory view of the log, plus the file it came from.
#[derive(Debug)]
pub struct StateLog {
    path: PathBuf,
    /// Held open for the signer's whole life. The exclusive lock on it is what
    /// stops a second process; the kernel releases it if this one dies, so a
    /// crash does not need an operator to clear anything.
    _lock: File,
    streams: BTreeMap<String, StreamState>,
    /// Every checkpoint hash this signer has ever produced.
    signed: BTreeSet<String>,
    /// `(stream_id, tree_size) -> checkpoint_hash`, for the fork check.
    by_size: BTreeMap<(String, i64), String>,
    tip: String,
    entries: u64,
}

impl StateLog {
    /// Open (or create) the state directory, replay the log and verify its chain.
    ///
    /// Takes an exclusive lock first: two signer processes sharing one state
    /// directory could each believe they hold the latest checkpoint and sign
    /// conflicting histories, which is precisely the fork the design forbids.
    pub fn open(dir: &Path) -> Result<Self, SignerError> {
        std::fs::create_dir_all(dir).map_err(|_| SignerError::StateUnavailable)?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join("state.lock"))
            .map_err(|_| SignerError::StateUnavailable)?;
        // An advisory exclusive lock: another live signer holds it, a dead one
        // does not.
        lock.try_lock().map_err(|_| SignerError::StateLocked)?;

        let path = dir.join("state.log");
        let mut log = Self {
            path: path.clone(),
            _lock: lock,
            streams: BTreeMap::new(),
            signed: BTreeSet::new(),
            by_size: BTreeMap::new(),
            tip: ZERO_HASH_HEX.to_owned(),
            entries: 0,
        };
        if path.exists() {
            log.replay()?;
        }
        Ok(log)
    }

    fn replay(&mut self) -> Result<(), SignerError> {
        let file = File::open(&self.path).map_err(|_| SignerError::StateUnavailable)?;
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|_| SignerError::StateCorrupt)?;
            if line.trim().is_empty() {
                continue;
            }
            let (entry, claimed_hash) = parse_line(&line)?;
            // 1. the line's own hash must match its contents
            let recomputed = entry_hash(&entry)?;
            if recomputed != claimed_hash {
                return Err(SignerError::StateCorrupt);
            }
            // 2. and it must point at the line before it
            let prev = field_str(&entry, "prev_entry_hash")?;
            if prev != self.tip {
                return Err(SignerError::StateCorrupt);
            }
            self.apply(&entry, &claimed_hash)?;
        }
        Ok(())
    }

    fn apply(&mut self, entry: &Value, line_hash: &str) -> Result<(), SignerError> {
        let stream_id = field_str(entry, "stream_id")?;
        let tree_size = field_int(entry, "tree_size")?;
        let payload_bytes = b64::decode(&field_str(entry, "checkpoint_payload_b64")?)
            .map_err(|_| SignerError::StateCorrupt)?;
        let payload_text =
            std::str::from_utf8(&payload_bytes).map_err(|_| SignerError::StateCorrupt)?;
        let payload = CheckpointPayload::from_canonical(payload_text)
            .map_err(|_| SignerError::StateCorrupt)?;
        let signature = field_str(entry, "signature")?;
        let checkpoint_hash = field_str(entry, "checkpoint_hash")?;
        // The recorded hash must be the hash of the recorded payload.
        if payload
            .checkpoint_hash_hex()
            .map_err(|_| SignerError::StateCorrupt)?
            != checkpoint_hash
        {
            return Err(SignerError::StateCorrupt);
        }
        if payload.tree_size != tree_size || payload.stream_id != stream_id {
            return Err(SignerError::StateCorrupt);
        }

        let levels = frontier_levels(entry)?;
        let frontier = Frontier::from_parts(
            u64::try_from(tree_size).map_err(|_| SignerError::StateCorrupt)?,
            levels,
        )
        .ok_or(SignerError::StateCorrupt)?;
        if hex_lower(&frontier.root()) != payload.root_hash {
            return Err(SignerError::StateCorrupt);
        }

        self.streams.insert(
            stream_id.clone(),
            StreamState {
                tree_size,
                root_hash: payload.root_hash.clone(),
                checkpoint_hash: checkpoint_hash.clone(),
                manifest_size: payload.manifest_size,
                manifest_head: payload.manifest_head.clone(),
                finished: field_bool(entry, "finished")?,
                frontier,
                checkpoint: StoredCheckpoint { payload, signature },
            },
        );
        self.signed.insert(checkpoint_hash.clone());
        self.by_size.insert((stream_id, tree_size), checkpoint_hash);
        self.tip = line_hash.to_owned();
        self.entries += 1;
        Ok(())
    }

    /// The state of one stream, if the signer has ever signed for it.
    #[must_use]
    pub fn stream(&self, stream_id: &str) -> Option<&StreamState> {
        self.streams.get(stream_id)
    }

    /// True when this signer produced that checkpoint itself (`R-GLB-02`).
    #[must_use]
    pub fn has_signed(&self, checkpoint_hash: &str) -> bool {
        self.signed.contains(checkpoint_hash)
    }

    /// Would signing this conflict with something already signed at that size?
    ///
    /// Defence in depth: the extension checks of `PROTOCOL.md` 11.2 should make
    /// this unreachable, so if it ever fires the signer's state and its caller
    /// disagree and the safe answer is to stop.
    #[must_use]
    pub fn would_fork(&self, stream_id: &str, tree_size: i64, checkpoint_hash: &str) -> bool {
        match self.by_size.get(&(stream_id.to_owned(), tree_size)) {
            None => false,
            Some(existing) => existing != checkpoint_hash,
        }
    }

    /// Number of entries in the log.
    #[must_use]
    pub const fn entries(&self) -> u64 {
        self.entries
    }

    /// Append one signed checkpoint, durably, before the caller is told.
    pub fn append(
        &mut self,
        checkpoint: &StoredCheckpoint,
        frontier: &Frontier,
        finished: bool,
    ) -> Result<(), SignerError> {
        let payload_bytes = checkpoint
            .payload
            .canonical_bytes()
            .map_err(|_| SignerError::StateUnavailable)?;
        let checkpoint_hash = checkpoint
            .payload
            .checkpoint_hash_hex()
            .map_err(|_| SignerError::StateUnavailable)?;
        let entry = Value::Object(vec![
            (
                "seq".to_owned(),
                Value::Int(i64::try_from(self.entries).unwrap_or(i64::MAX)),
            ),
            (
                "stream_id".to_owned(),
                Value::Str(checkpoint.payload.stream_id.clone()),
            ),
            (
                "tree_size".to_owned(),
                Value::Int(checkpoint.payload.tree_size),
            ),
            (
                "root_hash".to_owned(),
                Value::Str(checkpoint.payload.root_hash.clone()),
            ),
            (
                "checkpoint_hash".to_owned(),
                Value::Str(checkpoint_hash.clone()),
            ),
            (
                "key_id".to_owned(),
                Value::Str(checkpoint.payload.key_id.clone()),
            ),
            (
                "manifest_size".to_owned(),
                Value::Int(checkpoint.payload.manifest_size),
            ),
            (
                "manifest_head".to_owned(),
                Value::Str(checkpoint.payload.manifest_head.clone()),
            ),
            ("finished".to_owned(), Value::Bool(finished)),
            (
                "frontier".to_owned(),
                Value::Array(
                    frontier
                        .levels()
                        .iter()
                        .map(|held| Value::Str(held.map(|h| hex_lower(&h)).unwrap_or_default()))
                        .collect(),
                ),
            ),
            (
                "checkpoint_payload_b64".to_owned(),
                Value::Str(b64::encode(&payload_bytes)),
            ),
            (
                "signature".to_owned(),
                Value::Str(checkpoint.signature.clone()),
            ),
            ("prev_entry_hash".to_owned(), Value::Str(self.tip.clone())),
            // No transition metadata yet; key rotation is a later slice.
            ("transition_metadata".to_owned(), Value::Str(String::new())),
        ]);
        let hash = entry_hash(&entry)?;
        let line = Value::Object(vec![
            ("entry".to_owned(), entry.clone()),
            ("entry_hash".to_owned(), Value::Str(hash.clone())),
        ]);
        let text = abb_jcs::to_canonical_with(&line, &Limits::relaxed())
            .map_err(|_| SignerError::StateUnavailable)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| SignerError::StateUnavailable)?;
        file.write_all(text.as_bytes())
            .map_err(|_| SignerError::StateUnavailable)?;
        file.write_all(b"\n")
            .map_err(|_| SignerError::StateUnavailable)?;
        file.flush().map_err(|_| SignerError::StateUnavailable)?;
        // Durable before the signature leaves this process (R-SIG-09).
        file.sync_all().map_err(|_| SignerError::StateUnavailable)?;

        self.apply(&entry, &hash)?;
        Ok(())
    }

    /// Append one line to the audit log (`R-SIG-11`).
    ///
    /// Never contains key material, and never an event payload: only what the
    /// request was and how it ended.
    pub fn audit(&self, fields: &[(&str, Value)]) -> Result<(), SignerError> {
        let mut entries: Vec<(String, Value)> = fields
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect();
        entries.push(("at_ms".to_owned(), Value::Int(crate::now_ms())));
        let text = abb_jcs::to_canonical_with(&Value::Object(entries), &Limits::relaxed())
            .map_err(|_| SignerError::StateUnavailable)?;
        let audit_path = self.path.with_file_name("audit.log");
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(audit_path)
            .map_err(|_| SignerError::StateUnavailable)?;
        file.write_all(text.as_bytes())
            .map_err(|_| SignerError::StateUnavailable)?;
        file.write_all(b"\n")
            .map_err(|_| SignerError::StateUnavailable)?;
        file.flush().map_err(|_| SignerError::StateUnavailable)?;
        Ok(())
    }
}

/// `SHA-256(JCS(entry))`. The chain comes from `prev_entry_hash` inside the entry.
fn entry_hash(entry: &Value) -> Result<String, SignerError> {
    let bytes = abb_jcs::to_canonical_with(entry, &Limits::relaxed())
        .map_err(|_| SignerError::StateCorrupt)?;
    Ok(hex_lower(&Sha256::digest(bytes.as_bytes())))
}

fn parse_line(line: &str) -> Result<(Value, String), SignerError> {
    let value =
        abb_jcs::parse_str(line, &Limits::relaxed()).map_err(|_| SignerError::StateCorrupt)?;
    let entry = value.get("entry").ok_or(SignerError::StateCorrupt)?.clone();
    let hash = value
        .get("entry_hash")
        .and_then(Value::as_str)
        .ok_or(SignerError::StateCorrupt)?
        .to_owned();
    Ok((entry, hash))
}

fn field_str(entry: &Value, name: &str) -> Result<String, SignerError> {
    entry
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(SignerError::StateCorrupt)
}

fn field_int(entry: &Value, name: &str) -> Result<i64, SignerError> {
    entry
        .get(name)
        .and_then(Value::as_int)
        .ok_or(SignerError::StateCorrupt)
}

fn field_bool(entry: &Value, name: &str) -> Result<bool, SignerError> {
    match entry.get(name) {
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(SignerError::StateCorrupt),
    }
}

fn frontier_levels(entry: &Value) -> Result<Vec<Option<Hash>>, SignerError> {
    let items = entry
        .get("frontier")
        .and_then(Value::as_array)
        .ok_or(SignerError::StateCorrupt)?;
    let mut levels = Vec::with_capacity(items.len());
    for item in items {
        let text = item.as_str().ok_or(SignerError::StateCorrupt)?;
        if text.is_empty() {
            levels.push(None);
            continue;
        }
        let raw = hex_decode(text).map_err(|_| SignerError::StateCorrupt)?;
        let hash: Hash = raw.try_into().map_err(|_| SignerError::StateCorrupt)?;
        levels.push(Some(hash));
    }
    Ok(levels)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "abb-state-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_fork_check_only_fires_on_a_different_checkpoint_at_the_same_size() {
        let dir = temp_dir("fork-check");
        let mut log = StateLog::open(&dir).expect("opens");
        log.by_size.insert(("run-a".to_owned(), 4), "aa".repeat(32));

        assert!(
            !log.would_fork("run-a", 4, &"aa".repeat(32)),
            "the same checkpoint is not a fork"
        );
        assert!(
            log.would_fork("run-a", 4, &"bb".repeat(32)),
            "a different one is"
        );
        assert!(
            !log.would_fork("run-a", 5, &"bb".repeat(32)),
            "a different size is not"
        );
        assert!(
            !log.would_fork("run-b", 4, &"bb".repeat(32)),
            "another stream is not"
        );
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_second_open_while_the_first_is_alive_is_refused() {
        let dir = temp_dir("lock");
        let first = StateLog::open(&dir).expect("opens");
        assert_eq!(StateLog::open(&dir).unwrap_err(), SignerError::StateLocked);
        drop(first);
        // The lock is advisory and held by the process, so once the first one
        // is gone the next start works - including after a crash, which is why
        // this is an OS lock and not a marker file.
        let again = StateLog::open(&dir).expect("reopens once the holder is gone");
        drop(again);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_directory_has_no_streams_and_a_zero_tip() {
        let dir = temp_dir("empty");
        let log = StateLog::open(&dir).expect("opens");
        assert_eq!(log.entries(), 0);
        assert_eq!(log.tip, ZERO_HASH_HEX);
        assert!(log.stream("anything").is_none());
        assert!(!log.has_signed(&"aa".repeat(32)));
        drop(log);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
