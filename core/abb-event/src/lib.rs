//! The event envelope of `abb/1`: the 21 event types, envelope validation and
//! the Merkle leaf bytes.
//!
//! This lives in the Rust core because three components need exactly the same
//! answer: the ingestion service (before it commits), the signer (before it
//! signs, `PROTOCOL.md` 11.2 item 4) and the verifier (when it recomputes a
//! leaf). A second implementation in another language would be a second set of
//! rules (`AGENTS.md` 3.10).
//!
//! What this crate does **not** do: decide whether an event is *true*, or
//! whether policy allows the action it describes.

#![forbid(unsafe_code)]

use abb_checkpoint::{tagged_bytes, tags};
use abb_jcs::{Limits, Value};

/// The 21 event types of `PROTOCOL.md` 5.2. Checkpoints are not events (5.4),
/// so `CHECKPOINT_CREATED` is deliberately absent and must stay absent.
pub const EVENT_TYPES: [&str; 21] = [
    "RUN_STARTED",
    "COVERAGE_DECLARED",
    "ACTION_REQUESTED",
    "ACTION_AUTHORIZED",
    "ACTION_BLOCKED",
    "ACTION_DISPATCHED",
    "BROWSER_OBSERVATION",
    "API_CALL_OBSERVED",
    "ARTIFACT_CAPTURED",
    "POLICY_VIOLATION_DETECTED",
    "ACTION_SUCCEEDED",
    "ACTION_FAILED",
    "OUTCOME_UNKNOWN",
    "HUMAN_APPROVAL_REQUESTED",
    "HUMAN_APPROVAL_GRANTED",
    "HUMAN_APPROVAL_DENIED",
    "ML_ANALYSIS_COMPLETED",
    "SEMANTIC_INVARIANT_CHECKED",
    "SEMANTIC_VIOLATION_DETECTED",
    "PROMPT_SECURITY_ANALYSIS_COMPLETED",
    "RUN_FINISHED",
];

/// The three provenance sources (`PROTOCOL.md` 5.1).
pub const SOURCES: [&str; 3] = [
    "reported_by_adapter",
    "observed_by_local_gateway",
    "verified_by_black_box",
];

/// Adapter execution modes.
pub const MODES: [&str; 3] = ["REPLAY", "LIVE_LOCAL", "LIVE_EXTERNAL"];

/// Coverage levels (`PROTOCOL.md` section 7).
pub const COVERAGE_LEVELS: [&str; 3] = ["TASK_LEVEL", "STEP_OBSERVED", "STEP_GATED"];

/// Envelope fields this version defines. Anything else must start with `x_`.
const ENVELOPE_FIELDS: [&str; 12] = [
    "protocol_version",
    "schema_version",
    "run_id",
    "event_id",
    "sequence",
    "event_type",
    "created_at",
    "source",
    "provenance",
    "payload",
    "artifact_refs",
    "policy_ref",
];
/// Optional envelope fields that are defined but not required.
const OPTIONAL_ENVELOPE_FIELDS: [&str; 2] = ["commitments", "idempotency_key"];

/// Why an event envelope was rejected. These map onto the ingestion error
/// codes of `ERROR_HANDLING.md` 4.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventError {
    /// Not acceptable canonical JSON at all.
    Canonical(abb_jcs::CanonicalError),
    /// The bytes parse but are not the canonical form of their own value.
    NotCanonical,
    /// A required envelope field is missing.
    FieldMissing(&'static str),
    /// A field has the wrong type or an out-of-range value.
    FieldInvalid(&'static str),
    /// An undefined envelope field that does not start with `x_`.
    UnknownField(String),
    /// `event_type` is not one of the 21.
    UnknownEventType(String),
    /// `protocol_version` or `schema_version` is not supported.
    Unsupported(String),
}

impl EventError {
    /// The stable code a client branches on.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Canonical(e) => e.reason.as_str(),
            Self::NotCanonical => "CANONICAL_FORM_INVALID",
            Self::FieldMissing(_) | Self::FieldInvalid(_) => "VALIDATION_FAILED",
            Self::UnknownField(_) => "VALIDATION_FAILED",
            Self::UnknownEventType(_) => "UNKNOWN_EVENT_TYPE",
            Self::Unsupported(_) => "UNSUPPORTED",
        }
    }
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(e) => write!(f, "{e}"),
            Self::NotCanonical => f.write_str("CANONICAL_FORM_INVALID"),
            Self::FieldMissing(name) => write!(f, "VALIDATION_FAILED: missing {name}"),
            Self::FieldInvalid(name) => write!(f, "VALIDATION_FAILED: invalid {name}"),
            Self::UnknownField(name) => write!(f, "VALIDATION_FAILED: unknown field {name}"),
            Self::UnknownEventType(t) => write!(f, "UNKNOWN_EVENT_TYPE: {t}"),
            Self::Unsupported(v) => write!(f, "UNSUPPORTED: {v}"),
        }
    }
}

impl std::error::Error for EventError {}

impl From<abb_jcs::CanonicalError> for EventError {
    fn from(value: abb_jcs::CanonicalError) -> Self {
        Self::Canonical(value)
    }
}

/// What the ingestion service needs to know about an accepted event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEvent {
    /// The exact canonical bytes, to be stored and signed.
    pub canonical: Vec<u8>,
    /// `SHA-256(0x00 || "ABB1-EVENT" || 0x00 || canonical)`.
    pub leaf_hash: [u8; 32],
    /// Run identifier from the envelope.
    pub run_id: String,
    /// Event identifier from the envelope.
    pub event_id: String,
    /// Sequence from the envelope.
    pub sequence: i64,
    /// Event type from the envelope.
    pub event_type: String,
    /// Provenance source.
    pub source: String,
    /// Time claim in Unix milliseconds.
    pub created_at: i64,
    /// Idempotency key, when the producer supplied one.
    pub idempotency_key: Option<String>,
}

/// The Merkle leaf data for an event: `"ABB1-EVENT" || 0x00 || canonical`.
#[must_use]
pub fn leaf_bytes(canonical: &[u8]) -> Vec<u8> {
    tagged_bytes(tags::EVENT, canonical)
}

/// The Merkle leaf hash for an event.
#[must_use]
pub fn leaf_hash(canonical: &[u8]) -> [u8; 32] {
    abb_merkle::leaf_hash(&leaf_bytes(canonical))
}

fn is_lowercase_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (i, b) in bytes.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(b),
        };
        if !ok {
            return false;
        }
    }
    true
}

/// Validate one event's **already canonical** bytes.
///
/// This is the signer's and the verifier's entry point: the bytes must be
/// exactly the canonical form of their own value, because a signature covers
/// bytes, not values (`PROTOCOL.md` 3.1, 11.2 item 4).
pub fn validate(bytes: &[u8]) -> Result<ValidatedEvent, EventError> {
    validate_with(bytes, true)
}

/// Canonicalize loose JSON and validate the envelope.
///
/// This is the ingestion service's entry point: a producer may send its fields
/// in any order with any whitespace, and the server stores the canonical bytes
/// this returns (`DATABASE_AND_API_CONTRACTS.md` B1). It still rejects anything
/// the protocol forbids, such as a float or a duplicate key.
pub fn canonicalize_and_validate(bytes: &[u8]) -> Result<ValidatedEvent, EventError> {
    validate_with(bytes, false)
}

/// The envelope fields the **server** assigns, never the producer
/// (`PROTOCOL.md` 5.3: adapters propose events, they do not choose sequence
/// numbers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assignment {
    /// The run this event belongs to.
    pub run_id: String,
    /// The identifier the server minted.
    pub event_id: String,
    /// The sequence the stream head handed out.
    pub sequence: i64,
    /// Used only when the producer omitted `created_at`.
    pub created_at: i64,
}

/// The ingestion service's real entry point: take the producer's **raw bytes**,
/// insert the server-assigned envelope fields, canonicalize and validate.
///
/// Why the raw bytes and not a parsed object: a permissive JSON parser in the
/// service would silently drop a duplicate key or widen a float before the
/// protocol rules ever saw it. Parsing happens once, here, under the strict
/// rules (`PROTOCOL.md` 3.2, 3.3; `DATABASE_AND_API_CONTRACTS.md` B1).
///
/// A producer that supplies one of the assigned fields with a different value
/// is rejected rather than quietly overridden.
pub fn assign_and_validate(
    bytes: &[u8],
    assignment: &Assignment,
) -> Result<ValidatedEvent, EventError> {
    let limits = Limits::protocol();
    let parsed = abb_jcs::parse_bytes(bytes, &limits)?;
    let entries = parsed
        .as_object()
        .ok_or(EventError::FieldInvalid("event"))?
        .to_vec();

    let mut merged: Vec<(String, Value)> = Vec::with_capacity(entries.len() + 6);
    for (key, value) in entries {
        // Refuse a producer-chosen value that disagrees with the server's.
        let conflict = match key.as_str() {
            "protocol_version" => value.as_str() != Some(abb_checkpoint::PROTOCOL_VERSION),
            "schema_version" => value.as_int() != Some(1),
            "run_id" => value.as_str() != Some(assignment.run_id.as_str()),
            "event_id" => value.as_str() != Some(assignment.event_id.as_str()),
            "sequence" => value.as_int() != Some(assignment.sequence),
            _ => false,
        };
        if conflict {
            return Err(EventError::FieldInvalid(match key.as_str() {
                "protocol_version" => "protocol_version",
                "schema_version" => "schema_version",
                "run_id" => "run_id",
                "event_id" => "event_id",
                _ => "sequence",
            }));
        }
        if !matches!(
            key.as_str(),
            "protocol_version" | "schema_version" | "run_id" | "event_id" | "sequence"
        ) {
            merged.push((key, value));
        }
    }

    merged.push((
        "protocol_version".to_owned(),
        Value::Str(abb_checkpoint::PROTOCOL_VERSION.to_owned()),
    ));
    merged.push(("schema_version".to_owned(), Value::Int(1)));
    merged.push(("run_id".to_owned(), Value::Str(assignment.run_id.clone())));
    merged.push((
        "event_id".to_owned(),
        Value::Str(assignment.event_id.clone()),
    ));
    merged.push(("sequence".to_owned(), Value::Int(assignment.sequence)));
    if !merged.iter().any(|(k, _)| k == "created_at") {
        merged.push(("created_at".to_owned(), Value::Int(assignment.created_at)));
    }

    let value = Value::Object(merged);
    let canonical = abb_jcs::canonical_bytes(&value)?;
    validate_value(&value, canonical)
}

/// Shared implementation. `require_canonical` is the only difference between
/// the ingestion path and the signing path.
pub fn validate_with(bytes: &[u8], require_canonical: bool) -> Result<ValidatedEvent, EventError> {
    let limits = Limits::protocol();
    let value = abb_jcs::parse_bytes(bytes, &limits)?;

    let canonical = abb_jcs::canonical_bytes(&value)?;
    if require_canonical && canonical != bytes {
        return Err(EventError::NotCanonical);
    }
    validate_value(&value, canonical)
}

/// Envelope rules over an already parsed value and its canonical bytes.
fn validate_value(value: &Value, canonical: Vec<u8>) -> Result<ValidatedEvent, EventError> {
    let entries = value.as_object().ok_or(EventError::FieldInvalid("event"))?;
    for (key, _) in entries {
        let known = ENVELOPE_FIELDS.contains(&key.as_str())
            || OPTIONAL_ENVELOPE_FIELDS.contains(&key.as_str());
        if !known && !key.starts_with("x_") {
            return Err(EventError::UnknownField(key.clone()));
        }
    }

    let text = |name: &'static str| -> Result<String, EventError> {
        value
            .get(name)
            .ok_or(EventError::FieldMissing(name))?
            .as_str()
            .map(str::to_owned)
            .ok_or(EventError::FieldInvalid(name))
    };
    let int = |name: &'static str| -> Result<i64, EventError> {
        value
            .get(name)
            .ok_or(EventError::FieldMissing(name))?
            .as_int()
            .ok_or(EventError::FieldInvalid(name))
    };

    let protocol_version = text("protocol_version")?;
    if protocol_version != abb_checkpoint::PROTOCOL_VERSION {
        return Err(EventError::Unsupported(protocol_version));
    }
    let schema_version = int("schema_version")?;
    if schema_version != 1 {
        return Err(EventError::Unsupported(format!(
            "schema_version {schema_version}"
        )));
    }

    let run_id = text("run_id")?;
    if !is_lowercase_uuid(&run_id) {
        return Err(EventError::FieldInvalid("run_id"));
    }
    let event_id = text("event_id")?;
    if !is_lowercase_uuid(&event_id) {
        return Err(EventError::FieldInvalid("event_id"));
    }

    let sequence = int("sequence")?;
    if sequence < 0 {
        return Err(EventError::FieldInvalid("sequence"));
    }

    let event_type = text("event_type")?;
    if !EVENT_TYPES.contains(&event_type.as_str()) {
        return Err(EventError::UnknownEventType(event_type));
    }

    let created_at = int("created_at")?;
    if created_at < 0 {
        return Err(EventError::FieldInvalid("created_at"));
    }

    let source = text("source")?;
    if !SOURCES.contains(&source.as_str()) {
        return Err(EventError::FieldInvalid("source"));
    }

    validate_provenance(value)?;

    if value.get("payload").and_then(Value::as_object).is_none() {
        return Err(EventError::FieldInvalid("payload"));
    }

    if let Some(refs) = value.get("artifact_refs") {
        let items = refs
            .as_array()
            .ok_or(EventError::FieldInvalid("artifact_refs"))?;
        for item in items {
            let digest = item
                .as_str()
                .ok_or(EventError::FieldInvalid("artifact_refs"))?;
            if digest.len() != 64 || abb_jcs::hex_decode(digest).is_err() {
                return Err(EventError::FieldInvalid("artifact_refs"));
            }
        }
    }

    if let Some(policy_ref) = value.get("policy_ref") {
        if policy_ref.as_object().is_none() {
            return Err(EventError::FieldInvalid("policy_ref"));
        }
        if policy_ref
            .get("policy_id")
            .and_then(Value::as_str)
            .is_none()
        {
            return Err(EventError::FieldInvalid("policy_ref.policy_id"));
        }
        if policy_ref.get("policy_version").is_none() {
            return Err(EventError::FieldInvalid("policy_ref.policy_version"));
        }
    }

    if let Some(commitments) = value.get("commitments") {
        let fields = commitments
            .as_object()
            .ok_or(EventError::FieldInvalid("commitments"))?;
        for (name, digest) in fields {
            let hex = digest
                .as_str()
                .ok_or(EventError::FieldInvalid("commitments"))?;
            if hex.len() != 64 || abb_jcs::hex_decode(hex).is_err() {
                return Err(EventError::FieldInvalid("commitments"));
            }
            // A committed field must not also sit in the payload in clear
            // (PROTOCOL.md 5.5).
            if value.get("payload").and_then(|p| p.get(name)).is_some() {
                return Err(EventError::FieldInvalid("commitments"));
            }
        }
    }

    let idempotency_key = match value.get("idempotency_key") {
        None => None,
        Some(node) => {
            let key = node
                .as_str()
                .ok_or(EventError::FieldInvalid("idempotency_key"))?;
            if key.is_empty() || key.len() > 128 || !key.bytes().all(|b| (0x20..0x7f).contains(&b))
            {
                return Err(EventError::FieldInvalid("idempotency_key"));
            }
            Some(key.to_owned())
        }
    };

    Ok(ValidatedEvent {
        leaf_hash: leaf_hash(&canonical),
        canonical,
        run_id,
        event_id,
        sequence,
        event_type,
        source,
        created_at,
        idempotency_key,
    })
}

fn validate_provenance(value: &Value) -> Result<(), EventError> {
    let provenance = value
        .get("provenance")
        .ok_or(EventError::FieldMissing("provenance"))?;
    if provenance.as_object().is_none() {
        return Err(EventError::FieldInvalid("provenance"));
    }
    for name in ["adapter_name", "adapter_version", "execution_id"] {
        if provenance.get(name).and_then(Value::as_str).is_none() {
            return Err(EventError::FieldInvalid("provenance"));
        }
    }
    let mode = provenance
        .get("mode")
        .and_then(Value::as_str)
        .ok_or(EventError::FieldInvalid("provenance.mode"))?;
    if !MODES.contains(&mode) {
        return Err(EventError::FieldInvalid("provenance.mode"));
    }
    let coverage = provenance
        .get("observed_coverage")
        .and_then(Value::as_str)
        .ok_or(EventError::FieldInvalid("provenance.observed_coverage"))?;
    if !COVERAGE_LEVELS.contains(&coverage) {
        return Err(EventError::FieldInvalid("provenance.observed_coverage"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example() -> Value {
        Value::Object(vec![
            ("protocol_version".into(), Value::Str("abb/1".into())),
            ("schema_version".into(), Value::Int(1)),
            (
                "run_id".into(),
                Value::Str("00000000-0000-4000-8000-000000000001".into()),
            ),
            (
                "event_id".into(),
                Value::Str("00000000-0000-4000-8000-0000000000a1".into()),
            ),
            ("sequence".into(), Value::Int(3)),
            ("event_type".into(), Value::Str("ACTION_BLOCKED".into())),
            ("created_at".into(), Value::Int(1_760_000_000_000)),
            (
                "source".into(),
                Value::Str("observed_by_local_gateway".into()),
            ),
            (
                "provenance".into(),
                Value::Object(vec![
                    ("adapter_name".into(), Value::Str("replay".into())),
                    ("adapter_version".into(), Value::Str("0.1.0".into())),
                    ("execution_id".into(), Value::Str("replay-1".into())),
                    ("mode".into(), Value::Str("REPLAY".into())),
                    ("observed_coverage".into(), Value::Str("STEP_GATED".into())),
                ]),
            ),
            (
                "payload".into(),
                Value::Object(vec![("action_id".into(), Value::Str("act-2".into()))]),
            ),
            (
                "idempotency_key".into(),
                Value::Str("run1-act2-blocked".into()),
            ),
        ])
    }

    fn bytes_of(value: &Value) -> Vec<u8> {
        abb_jcs::canonical_bytes(value).expect("canonical")
    }

    fn with(key: &str, replacement: Option<Value>) -> Vec<u8> {
        let Value::Object(mut entries) = example() else {
            unreachable!()
        };
        entries.retain(|(k, _)| k != key);
        if let Some(value) = replacement {
            entries.push((key.to_owned(), value));
        }
        bytes_of(&Value::Object(entries))
    }

    #[test]
    fn the_example_event_validates_and_reports_its_fields() {
        let bytes = bytes_of(&example());
        let event = validate(&bytes).expect("valid");
        assert_eq!(event.canonical, bytes);
        assert_eq!(event.run_id, "00000000-0000-4000-8000-000000000001");
        assert_eq!(event.sequence, 3);
        assert_eq!(event.event_type, "ACTION_BLOCKED");
        assert_eq!(event.idempotency_key.as_deref(), Some("run1-act2-blocked"));
        assert_eq!(event.leaf_hash, leaf_hash(&bytes));
    }

    #[test]
    fn there_are_exactly_21_event_types_and_no_checkpoint_event() {
        assert_eq!(EVENT_TYPES.len(), 21);
        let mut sorted = EVENT_TYPES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 21);
        assert!(
            !EVENT_TYPES.contains(&"CHECKPOINT_CREATED"),
            "checkpoints are not events"
        );
    }

    #[test]
    fn leaf_bytes_are_tagged_and_differ_from_the_raw_canonical_bytes() {
        let bytes = bytes_of(&example());
        assert!(leaf_bytes(&bytes).starts_with(b"ABB1-EVENT\0"));
        assert_ne!(leaf_hash(&bytes), abb_merkle::leaf_hash(&bytes));
    }

    fn assignment() -> Assignment {
        Assignment {
            run_id: "00000000-0000-4000-8000-000000000001".into(),
            event_id: "00000000-0000-4000-8000-0000000000c3".into(),
            sequence: 7,
            created_at: 1_760_000_009_000,
        }
    }

    /// What an adapter actually posts: no envelope identifiers at all.
    const PRODUCER_BODY: &[u8] = br#"{
        "event_type": "ACTION_REQUESTED",
        "source": "reported_by_adapter",
        "provenance": {"adapter_name":"replay","adapter_version":"0.1.0",
                       "execution_id":"e1","mode":"REPLAY","observed_coverage":"STEP_GATED"},
        "payload": {"action_id":"a-1"}
    }"#;

    #[test]
    fn the_server_assigns_the_envelope_identifiers() {
        let event = assign_and_validate(PRODUCER_BODY, &assignment()).expect("accepted");
        assert_eq!(event.sequence, 7);
        assert_eq!(event.event_id, "00000000-0000-4000-8000-0000000000c3");
        assert_eq!(event.run_id, "00000000-0000-4000-8000-000000000001");
        // created_at was absent, so the server's claim is used.
        assert_eq!(event.created_at, 1_760_000_009_000);
        let text = std::str::from_utf8(&event.canonical).unwrap();
        assert!(abb_jcs::is_canonical(text));
        assert!(text.contains("\"protocol_version\":\"abb/1\""));
    }

    #[test]
    fn a_producer_timestamp_is_kept_as_its_own_claim() {
        let body = br#"{"event_type":"ACTION_REQUESTED","source":"reported_by_adapter",
            "created_at":1700000000000,
            "provenance":{"adapter_name":"replay","adapter_version":"0.1.0",
              "execution_id":"e1","mode":"REPLAY","observed_coverage":"STEP_GATED"},
            "payload":{}}"#;
        let event = assign_and_validate(body, &assignment()).expect("accepted");
        assert_eq!(event.created_at, 1_700_000_000_000);
    }

    #[test]
    fn a_duplicate_key_in_the_raw_body_is_still_caught() {
        // This is why the raw bytes reach the core: a permissive parser in the
        // service would keep the last value and lose the violation.
        let body = br#"{"event_type":"ACTION_REQUESTED","source":"reported_by_adapter",
            "provenance":{"adapter_name":"replay","adapter_version":"0.1.0",
              "execution_id":"e1","mode":"REPLAY","observed_coverage":"STEP_GATED"},
            "payload":{"amount":1,"amount":2}}"#;
        assert_eq!(
            assign_and_validate(body, &assignment())
                .unwrap_err()
                .as_str(),
            "DUPLICATE_KEY"
        );
    }

    #[test]
    fn a_float_in_the_raw_body_is_still_caught() {
        let body = br#"{"event_type":"ACTION_REQUESTED","source":"reported_by_adapter",
            "provenance":{"adapter_name":"replay","adapter_version":"0.1.0",
              "execution_id":"e1","mode":"REPLAY","observed_coverage":"STEP_GATED"},
            "payload":{"amount":1.5}}"#;
        assert_eq!(
            assign_and_validate(body, &assignment())
                .unwrap_err()
                .as_str(),
            "FLOAT_NOT_ALLOWED"
        );
    }

    #[test]
    fn a_producer_may_not_choose_its_own_sequence_or_ids() {
        for (field, fragment) in [
            ("sequence", r#""sequence":99"#),
            (
                "run_id",
                r#""run_id":"00000000-0000-4000-8000-000000000999""#,
            ),
            (
                "event_id",
                r#""event_id":"00000000-0000-4000-8000-000000000999""#,
            ),
            ("protocol_version", r#""protocol_version":"abb/2""#),
            ("schema_version", r#""schema_version":2"#),
        ] {
            let body = format!(
                r#"{{{fragment},"event_type":"ACTION_REQUESTED","source":"reported_by_adapter",
                   "provenance":{{"adapter_name":"replay","adapter_version":"0.1.0",
                     "execution_id":"e1","mode":"REPLAY","observed_coverage":"STEP_GATED"}},
                   "payload":{{}}}}"#
            );
            assert_eq!(
                assign_and_validate(body.as_bytes(), &assignment()).unwrap_err(),
                EventError::FieldInvalid(field),
                "{field}"
            );
        }
    }

    #[test]
    fn a_producer_echoing_the_assigned_values_is_accepted() {
        let body = br#"{"sequence":7,"run_id":"00000000-0000-4000-8000-000000000001",
            "event_id":"00000000-0000-4000-8000-0000000000c3","protocol_version":"abb/1",
            "schema_version":1,"event_type":"ACTION_REQUESTED","source":"reported_by_adapter",
            "provenance":{"adapter_name":"replay","adapter_version":"0.1.0",
              "execution_id":"e1","mode":"REPLAY","observed_coverage":"STEP_GATED"},
            "payload":{}}"#;
        assert!(assign_and_validate(body, &assignment()).is_ok());
    }

    #[test]
    fn the_ingestion_path_accepts_loose_json_and_returns_canonical_bytes() {
        let loose = br#"{ "schema_version":1, "protocol_version":"abb/1",
            "run_id":"00000000-0000-4000-8000-000000000001",
            "event_id":"00000000-0000-4000-8000-0000000000a1",
            "sequence":3, "event_type":"RUN_FINISHED", "created_at":1760000000000,
            "source":"reported_by_adapter",
            "provenance":{"adapter_name":"replay","adapter_version":"0.1.0",
              "execution_id":"r1","mode":"REPLAY","observed_coverage":"TASK_LEVEL"},
            "payload":{"final_state":"EXPORTED","event_count":4,"outcome":"ok"} }"#;
        // Strict rejects it; the ingestion path canonicalizes it.
        assert_eq!(validate(loose).unwrap_err(), EventError::NotCanonical);
        let event = canonicalize_and_validate(loose).expect("loose accepted");
        // What comes back is canonical, and validating that again is fine.
        assert!(abb_jcs::is_canonical(
            std::str::from_utf8(&event.canonical).unwrap()
        ));
        assert_eq!(
            validate(&event.canonical).expect("round trip").leaf_hash,
            event.leaf_hash
        );
    }

    #[test]
    fn the_ingestion_path_still_refuses_protocol_violations() {
        let float = br#"{"amount": 1.5}"#;
        assert_eq!(
            canonicalize_and_validate(float).unwrap_err().as_str(),
            "FLOAT_NOT_ALLOWED"
        );
        let duplicate = br#"{"a":1,"a":2}"#;
        assert_eq!(
            canonicalize_and_validate(duplicate).unwrap_err().as_str(),
            "DUPLICATE_KEY"
        );
    }

    #[test]
    fn non_canonical_bytes_are_rejected_even_when_they_parse() {
        let bytes = bytes_of(&example());
        let text = String::from_utf8(bytes).expect("utf8");
        let spaced = text.replace("\":", "\" :");
        assert_eq!(
            validate(spaced.as_bytes()).unwrap_err(),
            EventError::NotCanonical
        );
        // Key order matters too.
        let reordered = r#"{"schema_version":1,"protocol_version":"abb/1"}"#;
        assert_eq!(
            validate(reordered.as_bytes()).unwrap_err(),
            EventError::NotCanonical
        );
    }

    #[test]
    fn a_float_is_refused_before_any_envelope_check() {
        let bad = br#"{"amount":1.5}"#;
        let err = validate(bad).unwrap_err();
        assert_eq!(err.as_str(), "FLOAT_NOT_ALLOWED");
    }

    #[test]
    fn every_required_envelope_field_is_required() {
        for field in [
            "protocol_version",
            "schema_version",
            "run_id",
            "event_id",
            "sequence",
            "event_type",
            "created_at",
            "source",
            "provenance",
            "payload",
        ] {
            let bytes = with(field, None);
            let err = validate(&bytes).unwrap_err();
            assert!(
                matches!(
                    err,
                    EventError::FieldMissing(_) | EventError::FieldInvalid(_)
                ),
                "{field} was accepted as missing: {err:?}"
            );
        }
    }

    #[test]
    fn the_idempotency_key_is_optional_but_validated() {
        let without = with("idempotency_key", None);
        assert_eq!(validate(&without).expect("valid").idempotency_key, None);
        let empty = with("idempotency_key", Some(Value::Str(String::new())));
        assert_eq!(
            validate(&empty).unwrap_err(),
            EventError::FieldInvalid("idempotency_key")
        );
        let too_long = with("idempotency_key", Some(Value::Str("k".repeat(129))));
        assert_eq!(
            validate(&too_long).unwrap_err(),
            EventError::FieldInvalid("idempotency_key")
        );
        let non_ascii = with("idempotency_key", Some(Value::Str("key\u{e9}".into())));
        assert_eq!(
            validate(&non_ascii).unwrap_err(),
            EventError::FieldInvalid("idempotency_key")
        );
    }

    #[test]
    fn unknown_envelope_fields_are_refused_unless_they_start_with_x_() {
        let bytes = with("surprise", Some(Value::Int(1)));
        assert_eq!(
            validate(&bytes).unwrap_err(),
            EventError::UnknownField("surprise".to_owned())
        );
        let extension = with("x_vendor_note", Some(Value::Str("fine".into())));
        assert!(validate(&extension).is_ok());
    }

    #[test]
    fn unknown_event_types_and_versions_are_refused() {
        let bytes = with("event_type", Some(Value::Str("CHECKPOINT_CREATED".into())));
        assert_eq!(
            validate(&bytes).unwrap_err(),
            EventError::UnknownEventType("CHECKPOINT_CREATED".to_owned())
        );
        let bytes = with("protocol_version", Some(Value::Str("abb/2".into())));
        assert_eq!(validate(&bytes).unwrap_err().as_str(), "UNSUPPORTED");
        let bytes = with("schema_version", Some(Value::Int(2)));
        assert_eq!(validate(&bytes).unwrap_err().as_str(), "UNSUPPORTED");
    }

    #[test]
    fn identifiers_must_be_lowercase_uuids() {
        for field in ["run_id", "event_id"] {
            let upper = with(
                field,
                Some(Value::Str("00000000-0000-4000-8000-00000000000A".into())),
            );
            assert_eq!(
                validate(&upper).unwrap_err(),
                EventError::FieldInvalid(field)
            );
            let short = with(field, Some(Value::Str("not-a-uuid".into())));
            assert_eq!(
                validate(&short).unwrap_err(),
                EventError::FieldInvalid(field)
            );
        }
    }

    #[test]
    fn provenance_values_are_checked_against_the_protocol_sets() {
        let Value::Object(entries) = example() else {
            unreachable!()
        };
        let mut broken = entries.clone();
        for pair in &mut broken {
            if pair.0 == "provenance" {
                pair.1 = Value::Object(vec![
                    ("adapter_name".into(), Value::Str("replay".into())),
                    ("adapter_version".into(), Value::Str("0.1.0".into())),
                    ("execution_id".into(), Value::Str("x".into())),
                    ("mode".into(), Value::Str("SOMETHING_ELSE".into())),
                    ("observed_coverage".into(), Value::Str("STEP_GATED".into())),
                ]);
            }
        }
        let bytes = bytes_of(&Value::Object(broken));
        assert_eq!(
            validate(&bytes).unwrap_err(),
            EventError::FieldInvalid("provenance.mode")
        );
    }

    #[test]
    fn bad_source_values_are_refused() {
        let bytes = with("source", Some(Value::Str("trust_me".into())));
        assert_eq!(
            validate(&bytes).unwrap_err(),
            EventError::FieldInvalid("source")
        );
    }

    #[test]
    fn artifact_refs_must_be_64_char_lowercase_hex() {
        let good = with(
            "artifact_refs",
            Some(Value::Array(vec![Value::Str("ab".repeat(32))])),
        );
        assert!(validate(&good).is_ok());
        let upper = with(
            "artifact_refs",
            Some(Value::Array(vec![Value::Str("AB".repeat(32))])),
        );
        assert_eq!(
            validate(&upper).unwrap_err(),
            EventError::FieldInvalid("artifact_refs")
        );
        let short = with(
            "artifact_refs",
            Some(Value::Array(vec![Value::Str("abcd".into())])),
        );
        assert_eq!(
            validate(&short).unwrap_err(),
            EventError::FieldInvalid("artifact_refs")
        );
    }

    #[test]
    fn a_committed_field_may_not_also_be_in_the_payload_in_clear() {
        let Value::Object(mut entries) = example() else {
            unreachable!()
        };
        entries.retain(|(k, _)| k != "payload");
        entries.push((
            "payload".to_owned(),
            Value::Object(vec![("card".into(), Value::Str("4111111111111111".into()))]),
        ));
        entries.push((
            "commitments".to_owned(),
            Value::Object(vec![("card".into(), Value::Str("cd".repeat(32)))]),
        ));
        let bytes = bytes_of(&Value::Object(entries));
        assert_eq!(
            validate(&bytes).unwrap_err(),
            EventError::FieldInvalid("commitments")
        );
    }

    #[test]
    fn oversize_events_are_refused_by_the_protocol_limit() {
        let Value::Object(mut entries) = example() else {
            unreachable!()
        };
        entries.retain(|(k, _)| k != "payload");
        entries.push((
            "payload".to_owned(),
            Value::Object(vec![("blob".into(), Value::Str("x".repeat(70_000)))]),
        ));
        // Serializing it already exceeds the limit, so build the bytes loosely
        // and then validate them.
        let loose = abb_jcs::to_canonical_with(&Value::Object(entries), &Limits::relaxed())
            .expect("loose canonical");
        let err = validate(loose.as_bytes()).unwrap_err();
        assert_eq!(err.as_str(), "SIZE_EXCEEDED");
    }
}
