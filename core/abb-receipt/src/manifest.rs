//! The artifact manifest: a hash-linked chain, separate from the event tree.
//!
//! `PROTOCOL.md` 9 and `R-ART-03`..`R-ART-06`. Two things are worth keeping in
//! mind while reading this:
//!
//! * the manifest is **not** part of the event Merkle tree. It is its own
//!   chain, and the checkpoint commits to both (`R-ART-06`), so an artifact
//!   cannot be added or removed without changing a signed value;
//! * the artifact digest is the only untagged digest in the protocol
//!   (`D-03`), because the object key equals it. Domain separation still holds,
//!   because the manifest entry that commits to the digest is tagged.
//!
//! What a matching digest proves: these bytes are the bytes that were
//! committed. It does **not** prove the screenshot is genuine or the page was
//! truthful (`R-ART-07`).

use abb_checkpoint::{tagged_digest, tags, ZERO_HASH_HEX};
use abb_jcs::{hex_lower, Value};
use sha2::{Digest, Sha256};

/// The fields of a manifest entry (`PROTOCOL.md` 9), in canonical order.
pub const ENTRY_FIELDS: [&str; 9] = [
    "artifact_digest",
    "capture_method",
    "captured_at",
    "event_id",
    "index",
    "media_type",
    "prev_manifest_hash",
    "run_id",
    "size",
];

/// One parsed manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Position in the chain, from 0, no gaps.
    pub index: i64,
    /// The run this artifact belongs to.
    pub run_id: String,
    /// The `ARTIFACT_CAPTURED` event that announced it.
    pub event_id: String,
    /// `SHA-256(raw bytes)`, untagged (`D-03`).
    pub artifact_digest: String,
    /// Media type as captured.
    pub media_type: String,
    /// Size in bytes.
    pub size: i64,
    /// How it was captured, for example `html_snapshot`.
    pub capture_method: String,
    /// Capture time in Unix ms. A **claim**.
    pub captured_at: i64,
    /// The previous entry's hash, or 64 zeros at index 0.
    pub prev_manifest_hash: String,
    /// `SHA-256("ABB1-MANIFEST" || 0x00 || JCS(entry))`.
    pub entry_hash: String,
    /// The exact canonical bytes this entry was hashed from.
    pub canonical: Vec<u8>,
}

/// Why a manifest could not be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The entry bytes are not acceptable canonical JSON.
    NotCanonical(String),
    /// A field is missing or has the wrong type.
    Field(String),
    /// `index` is not the next one.
    IndexGap {
        /// The index the chain required next.
        expected: i64,
        /// The index actually found.
        found: i64,
    },
    /// `prev_manifest_hash` does not point at the previous entry.
    BrokenLink {
        /// The entry whose `prev_manifest_hash` does not link.
        index: i64,
    },
    /// An entry belongs to another run.
    WrongRun {
        /// The entry that names a different run.
        index: i64,
    },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotCanonical(why) => write!(f, "manifest entry is not canonical: {why}"),
            Self::Field(why) => write!(f, "manifest entry field: {why}"),
            Self::IndexGap { expected, found } => {
                write!(f, "manifest index {found} where {expected} was expected: an entry is missing or repeated")
            }
            Self::BrokenLink { index } => write!(
                f,
                "manifest entry {index} does not link to the one before it: the chain is broken"
            ),
            Self::WrongRun { index } => {
                write!(f, "manifest entry {index} belongs to another run")
            }
        }
    }
}

/// Parse one entry from its canonical bytes and compute its hash.
pub fn parse_entry(canonical: &[u8]) -> Result<ManifestEntry, ManifestError> {
    let text =
        std::str::from_utf8(canonical).map_err(|e| ManifestError::NotCanonical(e.to_string()))?;
    if !abb_jcs::is_canonical(text) {
        return Err(ManifestError::NotCanonical(
            "re-canonicalizing gives different bytes".to_owned(),
        ));
    }
    let value = abb_jcs::parse(text).map_err(|e| ManifestError::NotCanonical(e.to_string()))?;
    let entries = value
        .as_object()
        .ok_or_else(|| ManifestError::Field("not an object".to_owned()))?;
    let mut names: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
    names.sort_unstable();
    if names != ENTRY_FIELDS {
        return Err(ManifestError::Field(format!(
            "expected exactly the nine fields of PROTOCOL.md 9, found {names:?}"
        )));
    }

    let text_of = |name: &str| -> Result<String, ManifestError> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| ManifestError::Field(format!("{name} must be a string")))
    };
    let int_of = |name: &str| -> Result<i64, ManifestError> {
        value
            .get(name)
            .and_then(Value::as_int)
            .ok_or_else(|| ManifestError::Field(format!("{name} must be an integer")))
    };

    let artifact_digest = text_of("artifact_digest")?;
    if artifact_digest.len() != 64 || abb_jcs::hex_decode(&artifact_digest).is_err() {
        return Err(ManifestError::Field(
            "artifact_digest must be 64 lowercase hex characters".to_owned(),
        ));
    }
    let prev_manifest_hash = text_of("prev_manifest_hash")?;
    if prev_manifest_hash.len() != 64 || abb_jcs::hex_decode(&prev_manifest_hash).is_err() {
        return Err(ManifestError::Field(
            "prev_manifest_hash must be 64 lowercase hex characters".to_owned(),
        ));
    }
    let size = int_of("size")?;
    if size < 0 {
        return Err(ManifestError::Field("size must not be negative".to_owned()));
    }

    Ok(ManifestEntry {
        index: int_of("index")?,
        run_id: text_of("run_id")?,
        event_id: text_of("event_id")?,
        artifact_digest,
        media_type: text_of("media_type")?,
        size,
        capture_method: text_of("capture_method")?,
        captured_at: int_of("captured_at")?,
        prev_manifest_hash,
        entry_hash: hex_lower(&tagged_digest(tags::MANIFEST, canonical)),
        canonical: canonical.to_vec(),
    })
}

/// Check a whole chain for one run, returning its size and head.
///
/// The head is the hash of the last entry, or 64 zeros when the manifest is
/// empty (`PROTOCOL.md` 9).
pub fn check_chain(
    entries: &[ManifestEntry],
    run_id: &str,
) -> Result<(i64, String), ManifestError> {
    let mut head = ZERO_HASH_HEX.to_owned();
    for (position, entry) in entries.iter().enumerate() {
        let expected_index = i64::try_from(position).unwrap_or(i64::MAX);
        if entry.index != expected_index {
            return Err(ManifestError::IndexGap {
                expected: expected_index,
                found: entry.index,
            });
        }
        if entry.run_id != run_id {
            return Err(ManifestError::WrongRun { index: entry.index });
        }
        if entry.prev_manifest_hash != head {
            return Err(ManifestError::BrokenLink { index: entry.index });
        }
        head = entry.entry_hash.clone();
    }
    Ok((i64::try_from(entries.len()).unwrap_or(i64::MAX), head))
}

/// `SHA-256(raw bytes)`: the artifact digest, with no domain tag (`D-03`).
#[must_use]
pub fn artifact_digest(raw: &[u8]) -> String {
    hex_lower(&Sha256::digest(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_bytes(index: i64, prev: &str, digest: &str) -> Vec<u8> {
        let value = Value::Object(vec![
            ("artifact_digest".into(), Value::Str(digest.to_owned())),
            ("capture_method".into(), Value::Str("html_snapshot".into())),
            ("captured_at".into(), Value::Int(1_760_000_000_000 + index)),
            (
                "event_id".into(),
                Value::Str(format!("00000000-0000-4000-8000-{:012x}", index + 1)),
            ),
            ("index".into(), Value::Int(index)),
            ("media_type".into(), Value::Str("text/html".into())),
            ("prev_manifest_hash".into(), Value::Str(prev.to_owned())),
            (
                "run_id".into(),
                Value::Str("11111111-1111-4111-8111-111111111111".to_owned()),
            ),
            ("size".into(), Value::Int(12)),
        ]);
        abb_jcs::canonical_bytes(&value).expect("canonical")
    }

    fn chain_of(count: i64) -> Vec<ManifestEntry> {
        let mut entries = Vec::new();
        let mut prev = ZERO_HASH_HEX.to_owned();
        for index in 0..count {
            let digest = artifact_digest(format!("artifact {index}").as_bytes());
            let bytes = entry_bytes(index, &prev, &digest);
            let entry = parse_entry(&bytes).expect("parses");
            prev = entry.entry_hash.clone();
            entries.push(entry);
        }
        entries
    }

    const RUN: &str = "11111111-1111-4111-8111-111111111111";

    #[test]
    fn an_empty_manifest_has_a_zero_head() {
        assert_eq!(
            check_chain(&[], RUN).unwrap(),
            (0, ZERO_HASH_HEX.to_owned())
        );
    }

    #[test]
    fn a_valid_chain_reports_its_size_and_head() {
        let entries = chain_of(3);
        let (size, head) = check_chain(&entries, RUN).expect("valid chain");
        assert_eq!(size, 3);
        assert_eq!(head, entries[2].entry_hash);
        // The head is the hash of the last entry's canonical bytes, tagged.
        assert_eq!(
            head,
            hex_lower(&tagged_digest(tags::MANIFEST, &entries[2].canonical))
        );
    }

    #[test]
    fn a_broken_link_is_caught_and_named() {
        let mut entries = chain_of(3);
        entries[2].prev_manifest_hash = "ab".repeat(32);
        assert_eq!(
            check_chain(&entries, RUN).unwrap_err(),
            ManifestError::BrokenLink { index: 2 }
        );
    }

    #[test]
    fn a_missing_entry_is_caught() {
        let entries = chain_of(3);
        let shortened = vec![entries[0].clone(), entries[2].clone()];
        assert!(matches!(
            check_chain(&shortened, RUN).unwrap_err(),
            ManifestError::IndexGap {
                expected: 1,
                found: 2
            }
        ));
    }

    #[test]
    fn an_entry_from_another_run_is_caught() {
        let entries = chain_of(1);
        assert_eq!(
            check_chain(&entries, "22222222-2222-4222-8222-222222222222").unwrap_err(),
            ManifestError::WrongRun { index: 0 }
        );
    }

    #[test]
    fn a_non_canonical_entry_is_refused() {
        let bytes = entry_bytes(0, ZERO_HASH_HEX, &artifact_digest(b"x"));
        let text = String::from_utf8(bytes).unwrap().replace("\":", "\" :");
        assert!(matches!(
            parse_entry(text.as_bytes()).unwrap_err(),
            ManifestError::NotCanonical(_)
        ));
    }

    #[test]
    fn an_entry_with_extra_or_missing_fields_is_refused() {
        let value = Value::Object(vec![
            ("index".into(), Value::Int(0)),
            ("run_id".into(), Value::Str(RUN.to_owned())),
        ]);
        let bytes = abb_jcs::canonical_bytes(&value).unwrap();
        assert!(matches!(
            parse_entry(&bytes).unwrap_err(),
            ManifestError::Field(_)
        ));
    }

    #[test]
    fn the_artifact_digest_is_untagged() {
        // D-03: the object key equals the digest, so it cannot carry a tag.
        let bytes = b"a screenshot";
        assert_eq!(artifact_digest(bytes), hex_lower(&Sha256::digest(bytes)));
        assert_ne!(
            artifact_digest(bytes),
            hex_lower(&tagged_digest(tags::MANIFEST, bytes))
        );
    }

    #[test]
    fn changing_one_artifact_byte_changes_its_digest() {
        assert_ne!(artifact_digest(b"shot"), artifact_digest(b"shou"));
    }
}
