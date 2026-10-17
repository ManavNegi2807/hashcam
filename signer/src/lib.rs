//! The separate signer: the only process that holds the signing key.
//!
//! It does one thing. Given the previous checkpoint it issued and the canonical
//! bytes of the new events, it **recomputes the root itself** from a stored
//! Merkle frontier and signs a checkpoint over it. It never signs a root a
//! caller supplies (`D-12`, `R-SIG-03`).
//!
//! What that proves and what it does not (`R-SIG-06`): the signature says these
//! bytes are well formed, correctly ordered, and extend what this signer last
//! signed. It says nothing about whether the events are **true**. A compromised
//! ingestion service can still submit false but well-formed events; the
//! defences for that are the gateway, the witnesses and the anchors.
//!
//! Isolation (`R-SIG-01`, `R-SIG-02`): the configuration is a key path, a state
//! directory, one trusted ingestion public key and a rate limit. There is
//! nowhere to put a database credential, because it has none.

#![forbid(unsafe_code)]

pub mod state;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use abb_checkpoint::{tagged_bytes, tags, CheckpointPayload, PROTOCOL_VERSION, ZERO_HASH_HEX};
use abb_jcs::{b64, hex_lower, Limits, Value};
use abb_merkle::Frontier;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};

pub use state::{StateLog, StreamState};

/// The transport tag for a signing request's attestation (decision **D-20**).
///
/// This is deliberately **not** one of the nine protocol domain tags of
/// `PROTOCOL.md` section 4, and adding it does not bump `protocol_version`,
/// because the attestation is transport authentication between two local
/// services: it is never stored, never enters a receipt, and the offline
/// verifier never sees it. It still needs its own prefix so a signature over a
/// signing request can never be mistaken for a signature over a checkpoint.
///
/// **Needs your confirmation** (question Q7 in the implementation plan).
pub const SIGNREQ_TAG: &str = "ABB1-SIGNREQ";

/// The global stream of run roots (`PROTOCOL.md` 8.5).
pub const GLOBAL_STREAM: &str = "global";

/// How the signer is configured. Note what is absent: any database credential.
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory holding `state.log`, `audit.log` and the lock file.
    pub state_dir: PathBuf,
    /// File holding the 32-byte Ed25519 seed. Read once, never logged.
    pub key_path: PathBuf,
    /// The one caller allowed to ask for signatures.
    pub ingestion_public_key: [u8; 32],
    /// Requests per second, after which `RATE_LIMITED` is returned.
    pub rate_limit_per_second: u32,
}

/// The signer's error codes (`PROTOCOL.md` 11.4, `ERROR_HANDLING.md` 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// The caller is not authenticated for this stream.
    Unauthorized,
    /// No state for the stream and no valid genesis.
    UnknownStream,
    /// A first checkpoint that is not a valid genesis.
    BadGenesis,
    /// The result would not extend the signer's last checkpoint.
    NotExtending,
    /// The request would shrink the stream.
    SizeRegression,
    /// It conflicts with something already signed.
    ForkDetected,
    /// The append batch is malformed or unverifiable.
    BadAppendEvidence(String),
    /// `expected_root` differs from the root the signer computed.
    RootMismatch,
    /// An event is not strict canonical, or is wrong for this stream.
    BadEvent(String),
    /// The sequence is not continuous from the signer's state.
    GapOrOverlap,
    /// Over the signing rate limit.
    RateLimited,
    /// The state log's chain is broken. The signer refuses to sign.
    StateCorrupt,
    /// Another signer process holds this state directory.
    StateLocked,
    /// The state directory or key could not be read or written.
    StateUnavailable,
}

impl SignerError {
    /// The wire code. `BadEvent`/`BadAppendEvidence` carry a detail separately.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::UnknownStream => "UNKNOWN_STREAM",
            Self::BadGenesis => "BAD_GENESIS",
            Self::NotExtending => "NOT_EXTENDING",
            Self::SizeRegression => "SIZE_REGRESSION",
            Self::ForkDetected => "FORK_DETECTED",
            Self::BadAppendEvidence(_) => "BAD_APPEND_EVIDENCE",
            Self::RootMismatch => "ROOT_MISMATCH",
            Self::BadEvent(_) => "BAD_EVENT",
            Self::GapOrOverlap => "GAP_OR_OVERLAP",
            Self::RateLimited => "RATE_LIMITED",
            Self::StateCorrupt => "STATE_CORRUPT",
            Self::StateLocked => "STATE_LOCKED",
            Self::StateUnavailable => "STATE_UNAVAILABLE",
        }
    }

    /// Safe-to-return context. Never a path, a key or an event payload.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::BadEvent(why) | Self::BadAppendEvidence(why) => why.clone(),
            other => other.as_str().to_owned(),
        }
    }

    /// The HTTP status the signer's narrow API returns.
    #[must_use]
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::UnknownStream => 404,
            Self::RateLimited => 429,
            Self::StateCorrupt | Self::StateLocked | Self::StateUnavailable => 503,
            Self::NotExtending
            | Self::SizeRegression
            | Self::ForkDetected
            | Self::RootMismatch
            | Self::GapOrOverlap => 409,
            Self::BadGenesis | Self::BadAppendEvidence(_) | Self::BadEvent(_) => 422,
        }
    }
}

impl std::fmt::Display for SignerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.as_str(), self.detail())
    }
}

impl std::error::Error for SignerError {}

/// A checkpoint as it is stored and returned: payload plus signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCheckpoint {
    /// The signed payload.
    pub payload: CheckpointPayload,
    /// Lowercase hex Ed25519 signature over the payload's signing bytes.
    pub signature: String,
}

impl StoredCheckpoint {
    /// The JCS value, as the API returns it.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![
            ("payload".to_owned(), self.payload.to_value()),
            ("signature".to_owned(), Value::Str(self.signature.clone())),
        ])
    }

    /// Read one from a parsed value.
    pub fn from_value(value: &Value) -> Result<Self, SignerError> {
        let payload_value = value
            .get("payload")
            .ok_or_else(|| bad_request("prev_checkpoint.payload"))?;
        let payload = CheckpointPayload::from_value(payload_value)
            .map_err(|e| bad_request(&format!("prev_checkpoint.payload: {e}")))?;
        let signature = value
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("prev_checkpoint.signature"))?
            .to_owned();
        Ok(Self { payload, signature })
    }
}

/// The new leaves a request asks the signer to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Append {
    /// The sequence the batch starts at; must equal the signer's tree size.
    pub from_sequence: i64,
    /// Canonical event bytes, in order. **Not** digests: the signer must be
    /// able to re-derive everything it signs.
    pub events: Vec<Vec<u8>>,
    /// Canonical manifest entry bytes, in order.
    pub manifest_entries: Vec<Vec<u8>>,
}

/// A signing request (`PROTOCOL.md` 11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRequest {
    /// Run UUID, or `"global"`.
    pub stream_id: String,
    /// The checkpoint the caller believes is current, absent at genesis.
    pub prev_checkpoint: Option<StoredCheckpoint>,
    /// The new leaves.
    pub append: Append,
    /// Optional cross-check: the root the caller computed.
    pub expected_root: Option<String>,
    /// Ed25519 signature by the ingestion key over the request (D-20).
    pub caller_attestation: String,
}

impl SignRequest {
    /// The request as JCS, **without** `caller_attestation`.
    ///
    /// That omission is what makes the attestation well defined: it signs the
    /// request it accompanies.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = vec![("stream_id".to_owned(), Value::Str(self.stream_id.clone()))];
        if let Some(prev) = &self.prev_checkpoint {
            entries.push(("prev_checkpoint".to_owned(), prev.to_value()));
        }
        let mut append = vec![
            (
                "from_sequence".to_owned(),
                Value::Int(self.append.from_sequence),
            ),
            (
                "events".to_owned(),
                Value::Array(
                    self.append
                        .events
                        .iter()
                        .map(|e| Value::Str(b64::encode(e)))
                        .collect(),
                ),
            ),
        ];
        if !self.append.manifest_entries.is_empty() {
            append.push((
                "manifest_entries".to_owned(),
                Value::Array(
                    self.append
                        .manifest_entries
                        .iter()
                        .map(|e| Value::Str(b64::encode(e)))
                        .collect(),
                ),
            ));
        }
        entries.push(("append".to_owned(), Value::Object(append)));
        if let Some(root) = &self.expected_root {
            entries.push(("expected_root".to_owned(), Value::Str(root.clone())));
        }
        Value::Object(entries)
    }

    /// Parse a request from a parsed JSON value.
    pub fn from_value(value: &Value) -> Result<Self, SignerError> {
        let stream_id = value
            .get("stream_id")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("stream_id"))?
            .to_owned();
        let prev_checkpoint = match value.get("prev_checkpoint") {
            None | Some(Value::Null) => None,
            Some(prev) => Some(StoredCheckpoint::from_value(prev)?),
        };
        let append_value = value.get("append").ok_or_else(|| bad_request("append"))?;
        // A caller that sends digests instead of bytes has given the signer
        // nothing it can verify, so say so rather than failing obscurely.
        if append_value.get("leaf_hashes").is_some() {
            return Err(bad_request(
                "leaf_hashes are not accepted: the signer needs canonical event bytes (D-12)",
            ));
        }
        let from_sequence = append_value
            .get("from_sequence")
            .and_then(Value::as_int)
            .ok_or_else(|| bad_request("append.from_sequence"))?;
        let events = decode_list(append_value, "events")?;
        let manifest_entries = decode_list(append_value, "manifest_entries")?;
        let expected_root = value
            .get("expected_root")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let caller_attestation = value
            .get("caller_attestation")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        Ok(Self {
            stream_id,
            prev_checkpoint,
            append: Append {
                from_sequence,
                events,
                manifest_entries,
            },
            expected_root,
            caller_attestation,
        })
    }
}

fn decode_list(node: &Value, field: &str) -> Result<Vec<Vec<u8>>, SignerError> {
    match node.get(field) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let text = item
                    .as_str()
                    .ok_or_else(|| bad_request(&format!("{field} must be base64")))?;
                out.push(
                    b64::decode(text)
                        .map_err(|_| bad_request(&format!("{field} is not valid base64")))?,
                );
            }
            Ok(out)
        }
        Some(_) => Err(bad_request(&format!("{field} must be an array"))),
    }
}

fn bad_request(detail: &str) -> SignerError {
    SignerError::BadAppendEvidence(detail.to_owned())
}

/// The bytes a `caller_attestation` signs: `"ABB1-SIGNREQ" || 0x00 || JCS(request)`
/// with `caller_attestation` removed (decision **D-20**).
pub fn request_signing_bytes(request: &Value) -> Result<Vec<u8>, SignerError> {
    let entries = request
        .as_object()
        .ok_or_else(|| bad_request("the request must be a JSON object"))?;
    let stripped: Vec<(String, Value)> = entries
        .iter()
        .filter(|(key, _)| key != "caller_attestation")
        .cloned()
        .collect();
    let canonical = abb_jcs::to_canonical_with(&Value::Object(stripped), &Limits::relaxed())
        .map_err(|_| bad_request("the request is not acceptable JSON"))?;
    Ok(tagged_bytes(SIGNREQ_TAG, canonical.as_bytes()))
}

/// Unix milliseconds. A **claim** (`PROTOCOL.md` 10.4).
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

/// The signer.
#[derive(Debug)]
pub struct Signer {
    key: SigningKey,
    key_id: String,
    ingestion: VerifyingKey,
    log: StateLog,
    rate_limit: u32,
    recent: VecDeque<Instant>,
}

impl Signer {
    /// Load the key, open the state directory and verify the state log.
    ///
    /// Fails closed on a broken chain (`R-SIG-10`): the signer refuses to run
    /// rather than starting from a state it cannot vouch for.
    pub fn open(config: Config) -> Result<Self, SignerError> {
        let seed = std::fs::read(&config.key_path).map_err(|_| SignerError::StateUnavailable)?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| SignerError::StateUnavailable)?;
        let key = SigningKey::from_bytes(&seed);
        let key_id = abb_checkpoint::key_id_for(&key.verifying_key().to_bytes());
        let ingestion = VerifyingKey::from_bytes(&config.ingestion_public_key)
            .map_err(|_| SignerError::StateUnavailable)?;
        let log = StateLog::open(&config.state_dir)?;
        Ok(Self {
            key,
            key_id,
            ingestion,
            log,
            rate_limit: config.rate_limit_per_second,
            recent: VecDeque::new(),
        })
    }

    /// The signer's key id. The private half never leaves this process.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// What the signer last signed for a stream.
    #[must_use]
    pub fn state(&self, stream_id: &str) -> Option<&StreamState> {
        self.log.stream(stream_id)
    }

    /// Handle a request body: authenticate, validate, sign, record, return.
    pub fn sign_json(&mut self, body: &[u8]) -> Result<StoredCheckpoint, SignerError> {
        let value = abb_jcs::parse_bytes(body, &Limits::relaxed())
            .map_err(|e| bad_request(&format!("request is not acceptable JSON: {e}")))?;

        // 11.2 item 1: the caller is authenticated.
        let attestation = value
            .get("caller_attestation")
            .and_then(Value::as_str)
            .ok_or(SignerError::Unauthorized)?;
        let signing_bytes = request_signing_bytes(&value)?;
        let raw = abb_jcs::hex_decode(attestation).map_err(|_| SignerError::Unauthorized)?;
        let bytes: [u8; 64] = raw.try_into().map_err(|_| SignerError::Unauthorized)?;
        self.ingestion
            .verify_strict(&signing_bytes, &Signature::from_bytes(&bytes))
            .map_err(|_| SignerError::Unauthorized)?;

        // 11.2 item 9: rate limit, then record the outcome either way.
        self.check_rate_limit()?;

        let request = SignRequest::from_value(&value)?;
        let outcome = self.sign(&request);
        self.record(&request, &outcome);
        outcome
    }

    /// Validate and sign an already authenticated request.
    pub fn sign(&mut self, request: &SignRequest) -> Result<StoredCheckpoint, SignerError> {
        let stream_id = request.stream_id.clone();
        if stream_id.is_empty() {
            return Err(bad_request("stream_id"));
        }
        let known = self.log.stream(&stream_id).cloned();

        // 11.2 item 2: prev_checkpoint must be the signer's own last checkpoint.
        match (&known, &request.prev_checkpoint) {
            (None, Some(_)) => return Err(SignerError::UnknownStream),
            (Some(state), None) => {
                // Claiming genesis for a stream that already exists.
                let _ = state;
                return Err(SignerError::NotExtending);
            }
            (Some(state), Some(prev)) => {
                let claimed = prev
                    .payload
                    .checkpoint_hash_hex()
                    .map_err(|_| bad_request("prev_checkpoint"))?;
                if claimed != state.checkpoint_hash {
                    return Err(SignerError::NotExtending);
                }
            }
            (None, None) => {}
        }

        let current_size = known.as_ref().map_or(0, |s| s.tree_size);
        let added = i64::try_from(request.append.events.len()).unwrap_or(i64::MAX);

        // 11.2 item 3: no gap, no overlap.
        if request.append.from_sequence != current_size {
            return Err(if request.append.from_sequence + added < current_size {
                SignerError::SizeRegression
            } else {
                SignerError::GapOrOverlap
            });
        }

        // 11.2 item 6: an empty batch returns the identical stored checkpoint.
        if request.append.events.is_empty() && request.append.manifest_entries.is_empty() {
            return match known {
                None => Err(SignerError::UnknownStream),
                Some(state) => Ok(state.checkpoint),
            };
        }

        // 11.2 item 4: every leaf is checked before anything is signed.
        let mut frontier = known
            .as_ref()
            .map_or_else(Frontier::new, |state| state.frontier.clone());
        let mut finished = known.as_ref().is_some_and(|state| state.finished);
        if finished {
            return Err(SignerError::BadEvent(
                "nothing follows RUN_FINISHED (PROTOCOL.md 5.3)".to_owned(),
            ));
        }

        if stream_id == GLOBAL_STREAM {
            self.check_global_leaves(&request.append.events)?;
            for record in &request.append.events {
                frontier.push_leaf_data(&tagged_bytes(tags::RUNROOT, record));
            }
        } else {
            for (offset, bytes) in request.append.events.iter().enumerate() {
                let expected_sequence =
                    request.append.from_sequence + i64::try_from(offset).unwrap_or(i64::MAX);
                let event = abb_event::validate(bytes).map_err(|e| {
                    SignerError::BadEvent(format!("sequence {expected_sequence}: {e}"))
                })?;
                if event.run_id != stream_id {
                    return Err(SignerError::BadEvent(format!(
                        "sequence {expected_sequence}: run_id is not this stream"
                    )));
                }
                if event.sequence != expected_sequence {
                    return Err(SignerError::GapOrOverlap);
                }
                if expected_sequence == 0 && event.event_type != "RUN_STARTED" {
                    return Err(SignerError::BadEvent(
                        "the first event of a run stream must be RUN_STARTED".to_owned(),
                    ));
                }
                if finished {
                    return Err(SignerError::BadEvent(
                        "nothing follows RUN_FINISHED (PROTOCOL.md 5.3)".to_owned(),
                    ));
                }
                if event.event_type == "RUN_FINISHED" {
                    finished = true;
                }
                frontier.push_leaf_data(&tagged_bytes(tags::EVENT, bytes));
            }
        }

        let tree_size = i64::try_from(frontier.size()).unwrap_or(i64::MAX);
        let root_hash = hex_lower(&frontier.root());

        // 11.2 item 5: the optional cross-check.
        if let Some(expected) = &request.expected_root {
            if expected != &root_hash {
                return Err(SignerError::RootMismatch);
            }
        }

        // 11.2 item 7: the manifest chain, and the head the signer computes.
        let (manifest_size, manifest_head) = self.extend_manifest(&known, request)?;

        let payload = CheckpointPayload {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            stream_id: stream_id.clone(),
            tree_size,
            root_hash,
            manifest_size,
            manifest_head,
            prev_checkpoint_hash: known
                .as_ref()
                .map_or_else(|| ZERO_HASH_HEX.to_owned(), |s| s.checkpoint_hash.clone()),
            key_id: self.key_id.clone(),
            created_at: now_ms(),
        };
        // The genesis shape rule of PROTOCOL.md 10.3, checked on our own output.
        if known.is_none() && !payload.is_genesis_shaped() {
            return Err(SignerError::BadGenesis);
        }

        let checkpoint_hash = payload
            .checkpoint_hash_hex()
            .map_err(|_| SignerError::StateUnavailable)?;
        // 11.2 item 8: no fork.
        if self.log.would_fork(&stream_id, tree_size, &checkpoint_hash) {
            return Err(SignerError::ForkDetected);
        }

        let signature = payload
            .sign(&self.key)
            .map_err(|_| SignerError::StateUnavailable)?;
        let checkpoint = StoredCheckpoint { payload, signature };

        // Durable before the caller is told (R-SIG-09).
        self.log.append(&checkpoint, &frontier, finished)?;
        Ok(checkpoint)
    }

    /// For the global stream: every leaf must be a run-root record whose
    /// checkpoint this signer produced itself (`R-GLB-02`).
    fn check_global_leaves(&self, leaves: &[Vec<u8>]) -> Result<(), SignerError> {
        const FIELDS: [&str; 6] = [
            "checkpoint_hash",
            "finalized_at",
            "manifest_head",
            "root_hash",
            "run_id",
            "tree_size",
        ];
        for (offset, bytes) in leaves.iter().enumerate() {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| bad_request(&format!("run root {offset} is not UTF-8")))?;
            if !abb_jcs::is_canonical(text) {
                return Err(bad_request(&format!("run root {offset} is not canonical")));
            }
            let record = abb_jcs::parse(text)
                .map_err(|e| bad_request(&format!("run root {offset}: {e}")))?;
            let entries = record
                .as_object()
                .ok_or_else(|| bad_request(&format!("run root {offset} is not an object")))?;
            let mut names: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
            names.sort_unstable();
            if names != FIELDS {
                return Err(bad_request(&format!(
                    "run root {offset} does not have the six fields of PROTOCOL.md 8.5"
                )));
            }
            let checkpoint_hash = record
                .get("checkpoint_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| bad_request("run root checkpoint_hash"))?;
            if !self.log.has_signed(checkpoint_hash) {
                return Err(bad_request(&format!(
                    "NOT_IN_SIGNER_STATE_LOG: run root {offset} names a checkpoint this signer \
                     never produced"
                )));
            }
        }
        Ok(())
    }

    /// Extend the manifest chain and return its new size and head.
    ///
    /// The signer computes the head; a caller cannot assert one.
    fn extend_manifest(
        &self,
        known: &Option<StreamState>,
        request: &SignRequest,
    ) -> Result<(i64, String), SignerError> {
        let mut size = known.as_ref().map_or(0, |s| s.manifest_size);
        let mut head = known
            .as_ref()
            .map_or_else(|| ZERO_HASH_HEX.to_owned(), |s| s.manifest_head.clone());

        for (offset, bytes) in request.append.manifest_entries.iter().enumerate() {
            let text = std::str::from_utf8(bytes)
                .map_err(|_| bad_request(&format!("manifest entry {offset} is not UTF-8")))?;
            if !abb_jcs::is_canonical(text) {
                return Err(bad_request(&format!(
                    "manifest entry {offset} is not canonical"
                )));
            }
            let entry = abb_jcs::parse(text)
                .map_err(|e| bad_request(&format!("manifest entry {offset}: {e}")))?;
            let index = entry
                .get("index")
                .and_then(Value::as_int)
                .ok_or_else(|| bad_request("manifest entry index"))?;
            if index != size {
                return Err(bad_request(&format!(
                    "manifest entry {offset} has index {index}, expected {size}"
                )));
            }
            let prev = entry
                .get("prev_manifest_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| bad_request("manifest entry prev_manifest_hash"))?;
            if prev != head {
                return Err(bad_request(&format!(
                    "manifest entry {offset} does not link to the current head"
                )));
            }
            head = hex_lower(&abb_checkpoint::tagged_digest(tags::MANIFEST, bytes));
            size += 1;
        }
        Ok((size, head))
    }

    fn check_rate_limit(&mut self) -> Result<(), SignerError> {
        if self.rate_limit == 0 {
            return Ok(());
        }
        let now = Instant::now();
        let window = Duration::from_secs(1);
        while let Some(front) = self.recent.front() {
            if now.duration_since(*front) >= window {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.len() >= self.rate_limit as usize {
            return Err(SignerError::RateLimited);
        }
        self.recent.push_back(now);
        Ok(())
    }

    /// One audit line per request. No key material, no event payloads.
    fn record(&self, request: &SignRequest, outcome: &Result<StoredCheckpoint, SignerError>) {
        let (result, detail) = match outcome {
            Ok(checkpoint) => (
                "SIGNED".to_owned(),
                checkpoint.payload.checkpoint_hash_hex().unwrap_or_default(),
            ),
            Err(error) => (error.as_str().to_owned(), error.detail()),
        };
        let _ = self.log.audit(&[
            ("stream_id", Value::Str(request.stream_id.clone())),
            ("from_sequence", Value::Int(request.append.from_sequence)),
            (
                "event_count",
                Value::Int(i64::try_from(request.append.events.len()).unwrap_or(i64::MAX)),
            ),
            ("result", Value::Str(result)),
            ("detail", Value::Str(detail)),
        ]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_attestation_ignores_the_attestation_field() {
        // Otherwise the signature would have to sign itself.
        let base = Value::Object(vec![
            ("stream_id".to_owned(), Value::Str("run".to_owned())),
            (
                "append".to_owned(),
                Value::Object(vec![("from_sequence".to_owned(), Value::Int(0))]),
            ),
        ]);
        let with_attestation = {
            let Value::Object(mut entries) = base.clone() else {
                unreachable!()
            };
            entries.push(("caller_attestation".to_owned(), Value::Str("ff".repeat(64))));
            Value::Object(entries)
        };
        assert_eq!(
            request_signing_bytes(&base).unwrap(),
            request_signing_bytes(&with_attestation).unwrap()
        );
    }

    #[test]
    fn the_attestation_is_domain_separated_from_a_checkpoint() {
        let value = Value::Object(vec![("stream_id".to_owned(), Value::Str("run".to_owned()))]);
        let bytes = request_signing_bytes(&value).unwrap();
        assert!(bytes.starts_with(b"ABB1-SIGNREQ\0"));
        assert!(!bytes.starts_with(b"ABB1-CHECKPOINT\0"));
        // And it is not one of the nine protocol tags.
        assert!(!tags::ALL.contains(&SIGNREQ_TAG));
    }

    #[test]
    fn a_request_round_trips_through_its_value() {
        let request = SignRequest {
            stream_id: "run-1".to_owned(),
            prev_checkpoint: None,
            append: Append {
                from_sequence: 0,
                events: vec![b"{}".to_vec(), b"[]".to_vec()],
                manifest_entries: Vec::new(),
            },
            expected_root: Some("ab".repeat(32)),
            caller_attestation: String::new(),
        };
        let parsed = SignRequest::from_value(&request.to_value()).expect("parses");
        assert_eq!(parsed.stream_id, request.stream_id);
        assert_eq!(parsed.append, request.append);
        assert_eq!(parsed.expected_root, request.expected_root);
    }

    #[test]
    fn leaf_hashes_in_a_request_are_named_as_the_problem() {
        let value = Value::Object(vec![
            ("stream_id".to_owned(), Value::Str("run".to_owned())),
            (
                "append".to_owned(),
                Value::Object(vec![
                    ("from_sequence".to_owned(), Value::Int(0)),
                    ("leaf_hashes".to_owned(), Value::Array(vec![])),
                ]),
            ),
        ]);
        let err = SignRequest::from_value(&value).unwrap_err();
        assert!(
            matches!(err, SignerError::BadAppendEvidence(ref why) if why.contains("leaf_hashes"))
        );
    }

    #[test]
    fn error_codes_and_statuses_are_stable() {
        assert_eq!(SignerError::Unauthorized.http_status(), 401);
        assert_eq!(SignerError::UnknownStream.http_status(), 404);
        assert_eq!(SignerError::RateLimited.http_status(), 429);
        assert_eq!(SignerError::StateCorrupt.http_status(), 503);
        assert_eq!(SignerError::ForkDetected.http_status(), 409);
        assert_eq!(SignerError::BadEvent("x".into()).http_status(), 422);
        assert_eq!(SignerError::BadEvent("why".into()).detail(), "why");
    }
}
