//! Protocol records for `abb/1`: domain tags, checkpoints, keys and rotation.
//!
//! * [`tags`] holds the nine fixed domain tags of `PROTOCOL.md` section 4 and
//!   the one deliberate exception, the untagged artifact digest (D-03).
//! * [`CheckpointPayload`] is the signed checkpoint of section 10, with the
//!   chain rules of section 10.3 in [`check_extends`].
//! * [`KeyManifest`] is the out-of-band key list of section 10.5, including
//!   roles and `failure_domain` (D-15), and [`RotationRecord`] is the
//!   transition record signed by both the old and the new key.
//!
//! Signing lives here so that the signer, the CLI and a later WASM build share
//! one implementation (`R-CRY-06`). This crate does not decide *whether* a
//! checkpoint may be signed: that is the signer's validation (Step 4).

#![forbid(unsafe_code)]

mod approval;
pub use approval::{field_commitment, ApprovalStatement, Mandate, SALT_LEN};

use abb_jcs::{hex_decode, hex_lower, CanonicalError, Value};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// The fixed domain tags. Changing one needs a `protocol_version` bump.
pub mod tags {
    /// Event leaf data.
    pub const EVENT: &str = "ABB1-EVENT";
    /// Checkpoint signing payload.
    pub const CHECKPOINT: &str = "ABB1-CHECKPOINT";
    /// Artifact manifest entry.
    pub const MANIFEST: &str = "ABB1-MANIFEST";
    /// Witness signing payload.
    pub const WITNESS: &str = "ABB1-WITNESS";
    /// Key transition record.
    pub const KEYROTATE: &str = "ABB1-KEYROTATE";
    /// Global log leaf (run root), D-10.
    pub const RUNROOT: &str = "ABB1-RUNROOT";
    /// Salted field commitment, D-11.
    pub const FIELD: &str = "ABB1-FIELD";
    /// Human approval statement, D-16.
    pub const APPROVAL: &str = "ABB1-APPROVAL";
    /// Mandate, D-16.
    pub const MANDATE: &str = "ABB1-MANDATE";

    /// Every tag, for conformance checks.
    pub const ALL: [&str; 9] = [
        EVENT, CHECKPOINT, MANIFEST, WITNESS, KEYROTATE, RUNROOT, FIELD, APPROVAL, MANDATE,
    ];
}

/// A 32-byte digest.
pub type Hash = [u8; 32];

/// 64 zeros: the previous hash of a genesis checkpoint and an empty manifest head.
pub const ZERO_HASH_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The protocol version this crate implements.
pub const PROTOCOL_VERSION: &str = "abb/1";

/// `tag || 0x00 || data`, the input every tagged digest is taken over.
#[must_use]
pub fn tagged_bytes(tag: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 1 + data.len());
    out.extend_from_slice(tag.as_bytes());
    out.push(0x00);
    out.extend_from_slice(data);
    out
}

/// `SHA-256(tag || 0x00 || data)`.
#[must_use]
pub fn tagged_digest(tag: &str, data: &[u8]) -> Hash {
    Sha256::digest(tagged_bytes(tag, data)).into()
}

/// `SHA-256(raw bytes)` with **no** tag: the artifact digest exception (D-03).
///
/// The MinIO object key equals this digest, so it cannot carry a tag. Domain
/// separation still holds because the manifest entry that commits to it is
/// tagged with [`tags::MANIFEST`].
#[must_use]
pub fn artifact_digest(raw: &[u8]) -> Hash {
    Sha256::digest(raw).into()
}

/// `key_id = "ed25519:" || hex(SHA-256(public key bytes))`.
#[must_use]
pub fn key_id_for(public_key: &[u8; 32]) -> String {
    format!("ed25519:{}", hex_lower(&Sha256::digest(public_key)))
}

/// What went wrong with a checkpoint, a key or a chain link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    /// The canonical JSON was not acceptable.
    Canonical(CanonicalError),
    /// A required field was absent.
    FieldMissing(&'static str),
    /// A field had the wrong type or an impossible value.
    FieldInvalid(&'static str),
    /// An envelope field that this version does not define.
    UnknownField(String),
    /// A hash field was not 64 lowercase hex characters.
    BadHashHex(&'static str),
    /// `protocol_version` is not one this build supports.
    UnsupportedVersion(String),
    /// The Ed25519 signature did not verify.
    BadSignature,
    /// The signature was not 64 bytes, or the key not 32.
    BadKeyOrSignatureLength,
    /// The signing key is not in the key manifest.
    UnknownKey(String),
    /// The key exists but does not hold the role this use needs.
    WrongKeyRole,
    /// The key is retired or revoked.
    KeyNotActive,
    /// `prev_checkpoint_hash` does not point at the previous checkpoint.
    NotExtending,
    /// The tree would shrink.
    SizeRegression,
    /// Same size as an existing checkpoint but different contents.
    ForkDetected,
    /// A first checkpoint that is not a valid genesis.
    BadGenesis,
    /// The manifest would shrink.
    ManifestRegression,
}

impl CheckpointError {
    /// The wire form of the code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Canonical(e) => e.reason.as_str(),
            Self::FieldMissing(_) => "FIELD_MISSING",
            Self::FieldInvalid(_) => "FIELD_INVALID",
            Self::UnknownField(_) => "UNKNOWN_FIELD",
            Self::BadHashHex(_) => "NOT_HEX",
            Self::UnsupportedVersion(_) => "UNSUPPORTED",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::BadKeyOrSignatureLength => "BAD_LENGTH",
            Self::UnknownKey(_) => "UNKNOWN_KEY",
            Self::WrongKeyRole => "WRONG_KEY_ROLE",
            Self::KeyNotActive => "KEY_NOT_ACTIVE",
            Self::NotExtending => "NOT_EXTENDING",
            Self::SizeRegression => "SIZE_REGRESSION",
            Self::ForkDetected => "FORK_DETECTED",
            Self::BadGenesis => "BAD_GENESIS",
            Self::ManifestRegression => "MANIFEST_REGRESSION",
        }
    }
}

impl std::fmt::Display for CheckpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FieldMissing(name) | Self::FieldInvalid(name) | Self::BadHashHex(name) => {
                write!(f, "{}: {name}", self.as_str())
            }
            Self::UnknownField(name) | Self::UnknownKey(name) | Self::UnsupportedVersion(name) => {
                write!(f, "{}: {name}", self.as_str())
            }
            Self::Canonical(e) => write!(f, "{e}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl std::error::Error for CheckpointError {}

impl From<CanonicalError> for CheckpointError {
    fn from(value: CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, CheckpointError>;

/// The signed checkpoint payload of `PROTOCOL.md` 10.1.
///
/// Hashes are kept as lowercase hex strings because that is what gets
/// canonicalized and signed; converting to bytes early would lose the exact
/// form the signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointPayload {
    /// Always `"abb/1"` for this build.
    pub protocol_version: String,
    /// Run UUID, or `"global"` for the global log.
    pub stream_id: String,
    /// Number of committed events covered.
    pub tree_size: i64,
    /// `MTH` of those events, 64 hex characters.
    pub root_hash: String,
    /// Entries in the artifact manifest.
    pub manifest_size: i64,
    /// Manifest head, or 64 zeros when the manifest is empty.
    pub manifest_head: String,
    /// Previous checkpoint hash, or 64 zeros at genesis.
    pub prev_checkpoint_hash: String,
    /// The signer key this checkpoint claims.
    pub key_id: String,
    /// Creation time in Unix milliseconds. A **claim** (section 10.4).
    pub created_at: i64,
}

const CHECKPOINT_FIELDS: [&str; 9] = [
    "protocol_version",
    "stream_id",
    "tree_size",
    "root_hash",
    "manifest_size",
    "manifest_head",
    "prev_checkpoint_hash",
    "key_id",
    "created_at",
];

fn hex64(value: &str, field: &'static str) -> Result<()> {
    if value.len() != 64 || hex_decode(value).is_err() {
        return Err(CheckpointError::BadHashHex(field));
    }
    Ok(())
}

impl CheckpointPayload {
    /// Build the JCS value for this payload.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![
            (
                "protocol_version".to_owned(),
                Value::Str(self.protocol_version.clone()),
            ),
            ("stream_id".to_owned(), Value::Str(self.stream_id.clone())),
            ("tree_size".to_owned(), Value::Int(self.tree_size)),
            ("root_hash".to_owned(), Value::Str(self.root_hash.clone())),
            ("manifest_size".to_owned(), Value::Int(self.manifest_size)),
            (
                "manifest_head".to_owned(),
                Value::Str(self.manifest_head.clone()),
            ),
            (
                "prev_checkpoint_hash".to_owned(),
                Value::Str(self.prev_checkpoint_hash.clone()),
            ),
            ("key_id".to_owned(), Value::Str(self.key_id.clone())),
            ("created_at".to_owned(), Value::Int(self.created_at)),
        ])
    }

    /// Read a payload from a parsed value, rejecting anything unexpected.
    ///
    /// Unknown fields are rejected: a checkpoint is not an event, so the `x_`
    /// escape of `PROTOCOL.md` 3.3 does not apply to it.
    pub fn from_value(value: &Value) -> Result<Self> {
        let entries = value
            .as_object()
            .ok_or(CheckpointError::FieldInvalid("checkpoint payload"))?;
        for (key, _) in entries {
            if !CHECKPOINT_FIELDS.contains(&key.as_str()) {
                return Err(CheckpointError::UnknownField(key.clone()));
            }
        }
        let text = |name: &'static str| -> Result<String> {
            value
                .get(name)
                .ok_or(CheckpointError::FieldMissing(name))?
                .as_str()
                .map(str::to_owned)
                .ok_or(CheckpointError::FieldInvalid(name))
        };
        let int = |name: &'static str| -> Result<i64> {
            value
                .get(name)
                .ok_or(CheckpointError::FieldMissing(name))?
                .as_int()
                .ok_or(CheckpointError::FieldInvalid(name))
        };

        let payload = Self {
            protocol_version: text("protocol_version")?,
            stream_id: text("stream_id")?,
            tree_size: int("tree_size")?,
            root_hash: text("root_hash")?,
            manifest_size: int("manifest_size")?,
            manifest_head: text("manifest_head")?,
            prev_checkpoint_hash: text("prev_checkpoint_hash")?,
            key_id: text("key_id")?,
            created_at: int("created_at")?,
        };
        if payload.protocol_version != PROTOCOL_VERSION {
            return Err(CheckpointError::UnsupportedVersion(
                payload.protocol_version,
            ));
        }
        if payload.tree_size < 0 {
            return Err(CheckpointError::FieldInvalid("tree_size"));
        }
        if payload.manifest_size < 0 {
            return Err(CheckpointError::FieldInvalid("manifest_size"));
        }
        if payload.stream_id.is_empty() {
            return Err(CheckpointError::FieldInvalid("stream_id"));
        }
        hex64(&payload.root_hash, "root_hash")?;
        hex64(&payload.manifest_head, "manifest_head")?;
        hex64(&payload.prev_checkpoint_hash, "prev_checkpoint_hash")?;
        Ok(payload)
    }

    /// Parse a payload from canonical JSON text, requiring exact canonical form.
    pub fn from_canonical(text: &str) -> Result<Self> {
        let value = abb_jcs::parse(text)?;
        let payload = Self::from_value(&value)?;
        // Re-canonicalizing must give identical bytes, or the signature covers
        // bytes we are not looking at (PROTOCOL.md 3.1).
        if abb_jcs::to_canonical(&value)? != text {
            return Err(CheckpointError::FieldInvalid("non-canonical bytes"));
        }
        Ok(payload)
    }

    /// The canonical bytes of the payload.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(abb_jcs::canonical_bytes(&self.to_value())?)
    }

    /// `"ABB1-CHECKPOINT" || 0x00 || JCS(payload)`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(tagged_bytes(tags::CHECKPOINT, &self.canonical_bytes()?))
    }

    /// `checkpoint_hash = SHA-256(signing_bytes)`.
    ///
    /// The signature is **not** part of this, so re-signing an identical
    /// payload keeps the same hash (`PROTOCOL.md` 10.2).
    pub fn checkpoint_hash(&self) -> Result<Hash> {
        Ok(Sha256::digest(self.signing_bytes()?).into())
    }

    /// Hex form of [`Self::checkpoint_hash`].
    pub fn checkpoint_hash_hex(&self) -> Result<String> {
        Ok(hex_lower(&self.checkpoint_hash()?))
    }

    /// True when this is shaped like a genesis checkpoint.
    #[must_use]
    pub fn is_genesis_shaped(&self) -> bool {
        self.prev_checkpoint_hash == ZERO_HASH_HEX && self.tree_size >= 1
    }

    /// Sign with an Ed25519 key. Used by the signer and by vector generation.
    ///
    /// The returned signature is lowercase hex. The key never leaves the caller.
    pub fn sign(&self, key: &SigningKey) -> Result<String> {
        Ok(hex_lower(&key.sign(&self.signing_bytes()?).to_bytes()))
    }

    /// Verify a signature over this payload with `verifying_key`.
    ///
    /// Uses `verify_strict`, which rejects the small-order and non-canonical
    /// points that plain verification would accept.
    pub fn verify(&self, signature_hex: &str, verifying_key: &VerifyingKey) -> Result<()> {
        let raw =
            hex_decode(signature_hex).map_err(|_| CheckpointError::BadHashHex("signature"))?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| CheckpointError::BadKeyOrSignatureLength)?;
        let signature = Signature::from_bytes(&bytes);
        verifying_key
            .verify_strict(&self.signing_bytes()?, &signature)
            .map_err(|_| CheckpointError::BadSignature)
    }
}

/// Check that `next` legally extends `prev` (`PROTOCOL.md` 10.3).
///
/// `prev_hash` is the checkpoint hash the signer actually holds, not the one
/// the caller claims. Pass `None` for `prev` when the stream is unknown, which
/// makes this a genesis check.
pub fn check_extends(
    prev: Option<(&CheckpointPayload, &str)>,
    next: &CheckpointPayload,
) -> Result<()> {
    match prev {
        None => {
            if !next.is_genesis_shaped() {
                return Err(CheckpointError::BadGenesis);
            }
            Ok(())
        }
        Some((previous, prev_hash)) => {
            if previous.stream_id != next.stream_id {
                return Err(CheckpointError::FieldInvalid("stream_id"));
            }
            if next.tree_size < previous.tree_size {
                return Err(CheckpointError::SizeRegression);
            }
            if next.tree_size == previous.tree_size {
                // Legal only as an idempotent return of the identical checkpoint.
                return if next.root_hash == previous.root_hash
                    && next.manifest_head == previous.manifest_head
                    && next.manifest_size == previous.manifest_size
                {
                    Ok(())
                } else {
                    Err(CheckpointError::ForkDetected)
                };
            }
            if next.manifest_size < previous.manifest_size {
                return Err(CheckpointError::ManifestRegression);
            }
            if next.prev_checkpoint_hash != prev_hash {
                return Err(CheckpointError::NotExtending);
            }
            Ok(())
        }
    }
}

// --------------------------------------------------------------------------- //
// keys
// --------------------------------------------------------------------------- //

/// What a key is allowed to sign (`PROTOCOL.md` 10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Checkpoints.
    Signer,
    /// Witness statements.
    Witness,
    /// Human approvals.
    Approver,
    /// Mandates.
    MandateIssuer,
}

impl Role {
    /// Parse the wire form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "signer" => Some(Self::Signer),
            "witness" => Some(Self::Witness),
            "approver" => Some(Self::Approver),
            "mandate_issuer" => Some(Self::MandateIssuer),
            _ => None,
        }
    }

    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signer => "signer",
            Self::Witness => "witness",
            Self::Approver => "approver",
            Self::MandateIssuer => "mandate_issuer",
        }
    }
}

/// One entry of the key manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// `ed25519:<hex digest of the public key>`.
    pub key_id: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// What this key may sign.
    pub role: Role,
    /// Independence label (D-15); `None` when the deployment did not set one.
    pub failure_domain: Option<String>,
    /// Validity start, Unix ms. A claim.
    pub valid_from: i64,
    /// `active`, `retired` or `revoked`.
    pub status: String,
}

impl KeyEntry {
    /// True when the key may be used right now.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// The verifying key, or an error if the bytes are not a valid point.
    pub fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.public_key)
            .map_err(|_| CheckpointError::BadKeyOrSignatureLength)
    }
}

/// The out-of-band key list. It must reach a verifier through a channel
/// independent of the receipt (`PROTOCOL.md` 10.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyManifest {
    /// The entries, in file order.
    pub keys: Vec<KeyEntry>,
}

impl KeyManifest {
    /// Find a key by id.
    #[must_use]
    pub fn get(&self, key_id: &str) -> Option<&KeyEntry> {
        self.keys.iter().find(|k| k.key_id == key_id)
    }

    /// Find an active key by id and require a role.
    pub fn require(&self, key_id: &str, role: Role) -> Result<&KeyEntry> {
        let entry = self
            .get(key_id)
            .ok_or_else(|| CheckpointError::UnknownKey(key_id.to_owned()))?;
        if entry.role != role {
            return Err(CheckpointError::WrongKeyRole);
        }
        if !entry.is_active() {
            return Err(CheckpointError::KeyNotActive);
        }
        // A key_id that is not the digest of its own public key would let a
        // manifest point one id at another key's bytes.
        if key_id_for(&entry.public_key) != entry.key_id {
            return Err(CheckpointError::FieldInvalid("key_id"));
        }
        Ok(entry)
    }

    /// Find an active key by id for a role, without the self-consistency
    /// check of [`Self::require`]. Used for witnesses, whose statements name the
    /// witness by key id.
    pub fn require_any(&self, key_id: &str, role: Role) -> Result<&KeyEntry> {
        self.require(key_id, role)
    }

    /// Parse a manifest from a value shaped like `vectors/keys/test_keys.json`.
    pub fn from_value(value: &Value) -> Result<Self> {
        let list = value
            .get("keys")
            .ok_or(CheckpointError::FieldMissing("keys"))?
            .as_array()
            .ok_or(CheckpointError::FieldInvalid("keys"))?;
        let mut keys = Vec::with_capacity(list.len());
        for item in list {
            let text = |name: &'static str| -> Result<String> {
                item.get(name)
                    .ok_or(CheckpointError::FieldMissing(name))?
                    .as_str()
                    .map(str::to_owned)
                    .ok_or(CheckpointError::FieldInvalid(name))
            };
            let public_hex = text("public_key_hex")?;
            let raw = hex_decode(&public_hex)
                .map_err(|_| CheckpointError::BadHashHex("public_key_hex"))?;
            let public_key: [u8; 32] = raw
                .try_into()
                .map_err(|_| CheckpointError::BadKeyOrSignatureLength)?;
            let role_text = text("role")?;
            keys.push(KeyEntry {
                key_id: text("key_id")?,
                public_key,
                role: Role::parse(&role_text).ok_or(CheckpointError::FieldInvalid("role"))?,
                failure_domain: item
                    .get("failure_domain")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                valid_from: item
                    .get("valid_from")
                    .ok_or(CheckpointError::FieldMissing("valid_from"))?
                    .as_int()
                    .ok_or(CheckpointError::FieldInvalid("valid_from"))?,
                status: text("status")?,
            });
        }
        Ok(Self { keys })
    }

    /// True when two labels name different failure domains, and neither is unset.
    ///
    /// An unset label cannot be shown to be independent, so it is not (D-15).
    #[must_use]
    pub fn domains_independent(a: Option<&str>, b: Option<&str>) -> bool {
        match (a, b) {
            (Some(x), Some(y)) => x != y,
            _ => false,
        }
    }
}

/// What a witness signs (`PROTOCOL.md` 12): a statement that it checked a
/// checkpoint extends what it saw before.
///
/// `failure_domain` is part of the signed statement so a witness cannot later
/// claim to have been somewhere else (D-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessStatement {
    /// Who is signing.
    pub witness_id: String,
    /// The stream; witnesses sign `"global"` checkpoints (D-10).
    pub stream_id: String,
    /// The hash of the checkpoint being witnessed.
    pub checkpoint_hash: String,
    /// Its tree size.
    pub tree_size: i64,
    /// The witness's independence label.
    pub failure_domain: String,
    /// Unix ms. A claim.
    pub created_at: i64,
}

impl WitnessStatement {
    /// The JCS value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![
            ("witness_id".to_owned(), Value::Str(self.witness_id.clone())),
            ("stream_id".to_owned(), Value::Str(self.stream_id.clone())),
            (
                "checkpoint_hash".to_owned(),
                Value::Str(self.checkpoint_hash.clone()),
            ),
            ("tree_size".to_owned(), Value::Int(self.tree_size)),
            (
                "failure_domain".to_owned(),
                Value::Str(self.failure_domain.clone()),
            ),
            ("created_at".to_owned(), Value::Int(self.created_at)),
        ])
    }

    /// Read a statement from canonical text, rejecting anything unexpected.
    pub fn from_canonical(text: &str) -> Result<Self> {
        let value = abb_jcs::parse(text)?;
        if abb_jcs::to_canonical(&value)? != text {
            return Err(CheckpointError::FieldInvalid("non-canonical bytes"));
        }
        let entries = value
            .as_object()
            .ok_or(CheckpointError::FieldInvalid("statement"))?;
        let mut names: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        names.sort_unstable();
        if names
            != [
                "checkpoint_hash",
                "created_at",
                "failure_domain",
                "stream_id",
                "tree_size",
                "witness_id",
            ]
        {
            return Err(CheckpointError::FieldInvalid("statement fields"));
        }
        let text_of = |name: &'static str| -> Result<String> {
            value
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(CheckpointError::FieldInvalid(name))
        };
        let int_of = |name: &'static str| -> Result<i64> {
            value
                .get(name)
                .and_then(Value::as_int)
                .ok_or(CheckpointError::FieldInvalid(name))
        };
        let statement = Self {
            witness_id: text_of("witness_id")?,
            stream_id: text_of("stream_id")?,
            checkpoint_hash: text_of("checkpoint_hash")?,
            tree_size: int_of("tree_size")?,
            failure_domain: text_of("failure_domain")?,
            created_at: int_of("created_at")?,
        };
        hex64(&statement.checkpoint_hash, "checkpoint_hash")?;
        Ok(statement)
    }

    /// `"ABB1-WITNESS" || 0x00 || JCS(statement)`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(tagged_bytes(
            tags::WITNESS,
            &abb_jcs::canonical_bytes(&self.to_value())?,
        ))
    }

    /// Sign with the witness's key.
    pub fn sign(&self, key: &SigningKey) -> Result<String> {
        Ok(hex_lower(&key.sign(&self.signing_bytes()?).to_bytes()))
    }

    /// Verify a signature over this statement.
    pub fn verify(&self, signature_hex: &str, key: &VerifyingKey) -> Result<()> {
        let raw =
            hex_decode(signature_hex).map_err(|_| CheckpointError::BadHashHex("signature"))?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| CheckpointError::BadKeyOrSignatureLength)?;
        key.verify_strict(&self.signing_bytes()?, &Signature::from_bytes(&bytes))
            .map_err(|_| CheckpointError::BadSignature)
    }
}

/// A key transition record (`PROTOCOL.md` 10.5), signed by the old and new key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationRecord {
    /// The key being retired.
    pub old_key_id: String,
    /// The key taking over.
    pub new_key_id: String,
    /// The checkpoint from which the new key is in force.
    pub effective_checkpoint_hash: String,
    /// Unix ms. A claim.
    pub created_at: i64,
}

impl RotationRecord {
    /// The JCS value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![
            ("old_key_id".to_owned(), Value::Str(self.old_key_id.clone())),
            ("new_key_id".to_owned(), Value::Str(self.new_key_id.clone())),
            (
                "effective_checkpoint_hash".to_owned(),
                Value::Str(self.effective_checkpoint_hash.clone()),
            ),
            ("created_at".to_owned(), Value::Int(self.created_at)),
        ])
    }

    /// `"ABB1-KEYROTATE" || 0x00 || JCS(record)`.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        Ok(tagged_bytes(
            tags::KEYROTATE,
            &abb_jcs::canonical_bytes(&self.to_value())?,
        ))
    }

    /// Verify both signatures. A rotation is accepted only if the **old** key
    /// authorised it and the **new** key proved possession.
    pub fn verify_both(
        &self,
        old_signature_hex: &str,
        new_signature_hex: &str,
        old_key: &VerifyingKey,
        new_key: &VerifyingKey,
    ) -> Result<()> {
        let bytes = self.signing_bytes()?;
        for (sig_hex, key) in [(old_signature_hex, old_key), (new_signature_hex, new_key)] {
            let raw = hex_decode(sig_hex).map_err(|_| CheckpointError::BadHashHex("signature"))?;
            let arr: [u8; 64] = raw
                .try_into()
                .map_err(|_| CheckpointError::BadKeyOrSignatureLength)?;
            key.verify_strict(&bytes, &Signature::from_bytes(&arr))
                .map_err(|_| CheckpointError::BadSignature)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(label: &str) -> SigningKey {
        // Test keys only, derived from a label, exactly as the vectors do.
        SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
    }

    fn payload(tree_size: i64, prev: &str) -> CheckpointPayload {
        let leaves = abb_merkle_root(tree_size);
        CheckpointPayload {
            protocol_version: PROTOCOL_VERSION.to_owned(),
            stream_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            tree_size,
            root_hash: leaves,
            manifest_size: 0,
            manifest_head: ZERO_HASH_HEX.to_owned(),
            prev_checkpoint_hash: prev.to_owned(),
            key_id: key_id_for(&key("signer").verifying_key().to_bytes()),
            created_at: 1_760_000_100_000,
        }
    }

    /// Stand-in root: this crate does not depend on abb-merkle, so tests use a
    /// deterministic 64-hex value instead.
    fn abb_merkle_root(tree_size: i64) -> String {
        hex_lower(&Sha256::digest(format!("root-{tree_size}").as_bytes()))
    }

    #[test]
    fn every_domain_tag_is_present_and_distinct() {
        assert_eq!(tags::ALL.len(), 9);
        let mut sorted = tags::ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 9);
        for tag in tags::ALL {
            assert!(tag.starts_with("ABB1-"), "{tag}");
        }
    }

    #[test]
    fn tags_separate_domains() {
        let data = b"abb1 vector input";
        let mut digests: Vec<Hash> = tags::ALL.iter().map(|t| tagged_digest(t, data)).collect();
        digests.push(artifact_digest(data));
        let before = digests.len();
        digests.sort_unstable();
        digests.dedup();
        assert_eq!(
            digests.len(),
            before,
            "two domains produced the same digest"
        );
    }

    #[test]
    fn tagged_bytes_insert_exactly_one_zero_byte() {
        let out = tagged_bytes("ABB1-EVENT", b"x");
        assert_eq!(out, b"ABB1-EVENT\0x");
    }

    #[test]
    fn key_id_is_the_digest_of_the_public_key() {
        let signing = key("signer");
        let public = signing.verifying_key().to_bytes();
        assert_eq!(
            key_id_for(&public),
            format!("ed25519:{}", hex_lower(&Sha256::digest(public)))
        );
    }

    #[test]
    fn signature_round_trips_and_hash_excludes_the_signature() {
        let signing = key("signer");
        let cp = payload(4, ZERO_HASH_HEX);
        let sig_a = cp.sign(&signing).unwrap();
        let sig_b = cp.sign(&signing).unwrap();
        cp.verify(&sig_a, &signing.verifying_key()).unwrap();
        cp.verify(&sig_b, &signing.verifying_key()).unwrap();
        // Ed25519 is deterministic, and either way the hash must not move.
        assert_eq!(sig_a, sig_b);
        assert_eq!(cp.checkpoint_hash().unwrap(), cp.checkpoint_hash().unwrap());
    }

    #[test]
    fn a_flipped_signature_bit_fails_verification() {
        let signing = key("signer");
        let cp = payload(4, ZERO_HASH_HEX);
        let mut sig = hex_decode(&cp.sign(&signing).unwrap()).unwrap();
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        assert_eq!(
            cp.verify(&hex_lower(&sig), &signing.verifying_key())
                .unwrap_err(),
            CheckpointError::BadSignature
        );
    }

    #[test]
    fn a_different_key_fails_verification() {
        let cp = payload(4, ZERO_HASH_HEX);
        let sig = cp.sign(&key("signer")).unwrap();
        assert_eq!(
            cp.verify(&sig, &key("witness").verifying_key())
                .unwrap_err(),
            CheckpointError::BadSignature
        );
    }

    #[test]
    fn payload_round_trips_through_canonical_text() {
        let cp = payload(8, ZERO_HASH_HEX);
        let text = String::from_utf8(cp.canonical_bytes().unwrap()).unwrap();
        assert_eq!(CheckpointPayload::from_canonical(&text).unwrap(), cp);
    }

    #[test]
    fn non_canonical_or_unknown_fields_are_rejected() {
        let cp = payload(8, ZERO_HASH_HEX);
        let text = String::from_utf8(cp.canonical_bytes().unwrap()).unwrap();
        let spaced = text.replace("\":", "\" :");
        assert!(CheckpointPayload::from_canonical(&spaced).is_err());

        let mut value = cp.to_value();
        if let Value::Object(entries) = &mut value {
            entries.push(("surprise".to_owned(), Value::Int(1)));
        }
        assert_eq!(
            CheckpointPayload::from_value(&value).unwrap_err(),
            CheckpointError::UnknownField("surprise".to_owned())
        );
    }

    #[test]
    fn bad_hashes_and_versions_are_rejected() {
        let mut cp = payload(1, ZERO_HASH_HEX);
        cp.root_hash = "abc".to_owned();
        let value = cp.to_value();
        assert_eq!(
            CheckpointPayload::from_value(&value).unwrap_err(),
            CheckpointError::BadHashHex("root_hash")
        );

        let mut cp = payload(1, ZERO_HASH_HEX);
        cp.root_hash = "AB".repeat(32);
        assert!(
            CheckpointPayload::from_value(&cp.to_value()).is_err(),
            "uppercase hex"
        );

        let mut cp = payload(1, ZERO_HASH_HEX);
        cp.protocol_version = "abb/2".to_owned();
        assert_eq!(
            CheckpointPayload::from_value(&cp.to_value()).unwrap_err(),
            CheckpointError::UnsupportedVersion("abb/2".to_owned())
        );
    }

    #[test]
    fn chain_rules_match_the_protocol() {
        let genesis = payload(4, ZERO_HASH_HEX);
        let genesis_hash = genesis.checkpoint_hash_hex().unwrap();
        check_extends(None, &genesis).unwrap();

        // Genesis with a non-zero previous hash, or an empty tree, is not one.
        let bad = payload(4, &"cd".repeat(32));
        assert_eq!(
            check_extends(None, &bad).unwrap_err(),
            CheckpointError::BadGenesis
        );
        let empty = payload(0, ZERO_HASH_HEX);
        assert_eq!(
            check_extends(None, &empty).unwrap_err(),
            CheckpointError::BadGenesis
        );

        // A proper extension.
        let next = payload(8, &genesis_hash);
        check_extends(Some((&genesis, &genesis_hash)), &next).unwrap();

        // Growth with the wrong previous hash.
        let detached = payload(8, ZERO_HASH_HEX);
        assert_eq!(
            check_extends(Some((&genesis, &genesis_hash)), &detached).unwrap_err(),
            CheckpointError::NotExtending
        );

        // Shrinking.
        let smaller = payload(2, &genesis_hash);
        assert_eq!(
            check_extends(Some((&genesis, &genesis_hash)), &smaller).unwrap_err(),
            CheckpointError::SizeRegression
        );

        // Equal size, identical contents: idempotent and allowed.
        check_extends(Some((&genesis, &genesis_hash)), &genesis).unwrap();

        // Equal size, different root: a fork.
        let mut forked = genesis.clone();
        forked.root_hash = "ab".repeat(32);
        assert_eq!(
            check_extends(Some((&genesis, &genesis_hash)), &forked).unwrap_err(),
            CheckpointError::ForkDetected
        );

        // Manifest may not shrink.
        let mut with_manifest = genesis.clone();
        with_manifest.manifest_size = 3;
        let wm_hash = with_manifest.checkpoint_hash_hex().unwrap();
        let mut shrunk = payload(8, &wm_hash);
        shrunk.manifest_size = 1;
        assert_eq!(
            check_extends(Some((&with_manifest, &wm_hash)), &shrunk).unwrap_err(),
            CheckpointError::ManifestRegression
        );
    }

    #[test]
    fn key_manifest_enforces_role_status_and_self_consistency() {
        let signing = key("signer");
        let public = signing.verifying_key().to_bytes();
        let id = key_id_for(&public);
        let mut manifest = KeyManifest {
            keys: vec![KeyEntry {
                key_id: id.clone(),
                public_key: public,
                role: Role::Signer,
                failure_domain: Some("host:a/admin:alice".to_owned()),
                valid_from: 0,
                status: "active".to_owned(),
            }],
        };
        manifest.require(&id, Role::Signer).unwrap();
        assert_eq!(
            manifest.require(&id, Role::Approver).unwrap_err(),
            CheckpointError::WrongKeyRole
        );
        assert!(matches!(
            manifest.require("ed25519:nope", Role::Signer).unwrap_err(),
            CheckpointError::UnknownKey(_)
        ));

        manifest.keys[0].status = "revoked".to_owned();
        assert_eq!(
            manifest.require(&id, Role::Signer).unwrap_err(),
            CheckpointError::KeyNotActive
        );

        // An id that is not the digest of its own key is rejected.
        manifest.keys[0].status = "active".to_owned();
        manifest.keys[0].key_id = "ed25519:".to_owned() + &"00".repeat(32);
        let wrong_id = manifest.keys[0].key_id.clone();
        assert_eq!(
            manifest.require(&wrong_id, Role::Signer).unwrap_err(),
            CheckpointError::FieldInvalid("key_id")
        );
    }

    #[test]
    fn independence_needs_two_different_declared_domains() {
        assert!(KeyManifest::domains_independent(
            Some("host:a"),
            Some("host:b")
        ));
        assert!(!KeyManifest::domains_independent(
            Some("host:a"),
            Some("host:a")
        ));
        assert!(!KeyManifest::domains_independent(None, Some("host:b")));
        assert!(!KeyManifest::domains_independent(None, None));
    }

    #[test]
    fn rotation_needs_both_signatures() {
        let old = key("old");
        let new = key("new");
        let record = RotationRecord {
            old_key_id: key_id_for(&old.verifying_key().to_bytes()),
            new_key_id: key_id_for(&new.verifying_key().to_bytes()),
            effective_checkpoint_hash: "ab".repeat(32),
            created_at: 1_760_000_000_000,
        };
        let bytes = record.signing_bytes().unwrap();
        let old_sig = hex_lower(&old.sign(&bytes).to_bytes());
        let new_sig = hex_lower(&new.sign(&bytes).to_bytes());
        record
            .verify_both(
                &old_sig,
                &new_sig,
                &old.verifying_key(),
                &new.verifying_key(),
            )
            .unwrap();
        // Only the new key signing is not enough.
        assert_eq!(
            record
                .verify_both(
                    &new_sig,
                    &new_sig,
                    &old.verifying_key(),
                    &new.verifying_key()
                )
                .unwrap_err(),
            CheckpointError::BadSignature
        );
    }
}
