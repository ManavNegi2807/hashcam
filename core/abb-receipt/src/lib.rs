//! Receipts: the file an auditor checks, and the code that checks it.
//!
//! `PROTOCOL.md` 15 defines the container (`D-04`: a ZIP holding a JCS
//! `receipt.json` and an optional `artifacts/` folder) and 16 defines the
//! verification procedure. This crate implements both, plus the builder that
//! turns an export bundle into a receipt.
//!
//! Two rules shape everything here:
//!
//! * **the verifier never stops at the first failure.** It fills every
//!   dimension it can, because "where is it broken" is the product
//!   (`PROTOCOL.md` 16, `R-REC-02`);
//! * **missing evidence is `UNKNOWN`, never `PASS`** (`R-COV-05`). A receipt
//!   that omits something required comes back `INCOMPLETE`, not `VALID`.
//!
//! What a `VALID` result means, stated here because it is easy to overclaim:
//! the signed history has not changed relative to the checkpoints, the events
//! are well formed and in order, and the declared coverage matches the
//! evidence. It does **not** mean the task was safe, correct, authorized or
//! actually executed as described (`R-REC-06`).

#![forbid(unsafe_code)]

mod advisory;
mod approvals;
mod build;
mod container;
pub mod manifest;

use std::collections::{BTreeMap, BTreeSet};

use abb_checkpoint::{tagged_bytes, tags, CheckpointPayload, KeyManifest, Role};
use abb_jcs::{b64, hex_lower, Limits, Value};
use abb_merkle::{leaf_hash, verify_consistency, verify_inclusion, Hash};
use abb_verify::{Dimension, Overall, Profile, ReceiptShape, Report, Status};

pub use advisory::{check_anomaly, check_prompt_security, check_semantic};
pub use approvals::{
    check_approvals, check_disclosures, check_mandate, run_declares_mandate, ApprovalRecord,
    DisclosureRecord, MandateRecord,
};
pub use build::build;
pub use container::{read_container, write_container, ContainerError, ReceiptFile};

/// The receipt schema this build reads and writes.
pub const SCHEMA_VERSION: i64 = 1;

/// Why a receipt could not even be read as a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// The container or the JSON was unreadable.
    Unreadable(String),
    /// A required field is missing or has the wrong type.
    Field(String),
    /// The protocol or schema version is not supported by this build.
    Unsupported(String),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(why) => write!(f, "unreadable: {why}"),
            Self::Field(why) => write!(f, "field: {why}"),
            Self::Unsupported(why) => write!(f, "unsupported: {why}"),
        }
    }
}

impl std::error::Error for ReceiptError {}

type Result<T> = std::result::Result<T, ReceiptError>;

fn field(why: impl Into<String>) -> ReceiptError {
    ReceiptError::Field(why.into())
}

// --------------------------------------------------------------------------- //
// the parsed receipt
// --------------------------------------------------------------------------- //

/// One event as a receipt carries it: the canonical bytes plus its proof.
#[derive(Debug, Clone)]
pub struct ReceiptEvent {
    /// Exactly the bytes that were hashed into the tree.
    pub canonical: Vec<u8>,
    /// Position in the tree.
    pub leaf_index: u64,
    /// Tree size the proof is against.
    pub tree_size: u64,
    /// Audit path.
    pub path: Vec<Hash>,
}

/// One checkpoint as a receipt carries it.
#[derive(Debug, Clone)]
pub struct ReceiptCheckpoint {
    /// The exact signed bytes.
    pub payload_bytes: Vec<u8>,
    /// The parsed payload.
    pub payload: CheckpointPayload,
    /// Hex signature.
    pub signature: String,
    /// Consistency proof from the previous checkpoint in this chain.
    pub consistency_from_previous: Vec<Hash>,
}

/// The run's place in the global log (`D-10`).
#[derive(Debug, Clone)]
pub struct GlobalInclusion {
    /// The canonical run-root record for this run.
    pub record: Vec<u8>,
    /// Its position in the global tree.
    pub leaf_index: u64,
    /// The global tree size the proof is against.
    pub tree_size: u64,
    /// Audit path in the global tree.
    pub path: Vec<Hash>,
    /// The global checkpoint chain, oldest first.
    pub checkpoints: Vec<ReceiptCheckpoint>,
}

/// A parsed receipt.
#[derive(Debug, Clone, Default)]
pub struct Receipt {
    /// `"abb/1"`.
    pub protocol_version: String,
    /// Receipt layout version.
    pub schema_version: i64,
    /// Run identity and coverage claims.
    pub run_id: String,
    /// Adapter that produced the run.
    pub adapter_name: String,
    /// Adapter version.
    pub adapter_version: String,
    /// What the run claimed to achieve.
    pub declared_coverage: String,
    /// What the adapter reported observing.
    pub observed_coverage: String,
    /// `LOCAL_ONLY` or `CONNECTED_EVIDENCE`.
    pub profile: String,
    /// Events in sequence order.
    pub events: Vec<ReceiptEvent>,
    /// Checkpoint chain, oldest first.
    pub checkpoints: Vec<ReceiptCheckpoint>,
    /// Policy identity.
    pub policy_id: String,
    /// Policy version.
    pub policy_version: i64,
    /// Global-log inclusion, required by `D-10`.
    pub global_log: Option<GlobalInclusion>,
    /// How to obtain the verification keys.
    pub key_manifest_ref: String,
    /// Exporter identity.
    pub exporter: String,
    /// Whether any timestamp carries trusted-timestamp evidence.
    pub timestamps_claimed: bool,
    /// Canonical bytes of each artifact manifest entry, in index order.
    pub manifest_entries: Vec<Vec<u8>>,
    /// Witness signatures over the final global checkpoint.
    pub witnesses: Vec<WitnessRecord>,
    /// Anchor publications of global checkpoints.
    pub anchors: Vec<AnchorRecord>,
    /// Signed human approvals (`PROTOCOL.md` 5.6).
    pub approvals: Vec<ApprovalRecord>,
    /// The signed mandate, when the run had one (`PROTOCOL.md` 5.7).
    pub mandate: Option<MandateRecord>,
    /// Fields the exporter chose to reveal (`PROTOCOL.md` 5.5).
    pub disclosures: Vec<DisclosureRecord>,
}

/// One witness signature as a receipt carries it.
#[derive(Debug, Clone)]
pub struct WitnessRecord {
    /// The exact signed statement bytes.
    pub statement_bytes: Vec<u8>,
    /// Hex signature.
    pub signature: String,
}

/// One anchor publication (`PROTOCOL.md` 13).
#[derive(Debug, Clone)]
pub struct AnchorRecord {
    /// The anchored global checkpoint.
    pub checkpoint_hash: String,
    /// Its tree size.
    pub tree_size: i64,
    /// Where it was published, for example a Git repository path.
    pub location: String,
    /// The administrative domain of the publisher (D-15).
    pub anchor_domain: String,
    /// When it was published. A claim; a Git commit time is not a trusted timestamp.
    pub published_at: i64,
}

fn as_hash(text: &str) -> Result<Hash> {
    let raw = abb_jcs::hex_decode(text).map_err(|_| field("not lowercase hex"))?;
    raw.try_into()
        .map_err(|_| field("a digest must be 32 bytes"))
}

fn path_of(node: &Value, name: &str) -> Result<Vec<Hash>> {
    let items = match node.get(name) {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(field(format!("{name} must be an array"))),
    };
    items
        .iter()
        .map(|item| {
            as_hash(
                item.as_str()
                    .ok_or_else(|| field(format!("{name} element")))?,
            )
        })
        .collect()
}

fn text_of(node: &Value, name: &str) -> Result<String> {
    node.get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| field(format!("missing {name}")))
}

fn int_of(node: &Value, name: &str) -> Result<i64> {
    node.get(name)
        .and_then(Value::as_int)
        .ok_or_else(|| field(format!("missing {name}")))
}

fn bytes_of(node: &Value, name: &str) -> Result<Vec<u8>> {
    b64::decode(&text_of(node, name)?).map_err(|_| field(format!("{name} is not base64")))
}

fn checkpoint_of(node: &Value) -> Result<ReceiptCheckpoint> {
    let payload_bytes = bytes_of(node, "payload_b64")?;
    let text = std::str::from_utf8(&payload_bytes).map_err(|_| field("payload is not UTF-8"))?;
    let payload = CheckpointPayload::from_canonical(text)
        .map_err(|e| field(format!("checkpoint payload: {e}")))?;
    Ok(ReceiptCheckpoint {
        payload_bytes,
        payload,
        signature: text_of(node, "signature")?,
        consistency_from_previous: path_of(node, "consistency_from_previous")?,
    })
}

impl Receipt {
    /// Parse `receipt.json`.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value = abb_jcs::parse_bytes(bytes, &Limits::relaxed())
            .map_err(|e| ReceiptError::Unreadable(e.to_string()))?;

        let protocol_version = text_of(&value, "protocol_version")?;
        if protocol_version != abb_checkpoint::PROTOCOL_VERSION {
            return Err(ReceiptError::Unsupported(format!(
                "protocol_version {protocol_version}"
            )));
        }
        let schema_version = int_of(&value, "schema_version")?;
        if schema_version != SCHEMA_VERSION {
            return Err(ReceiptError::Unsupported(format!(
                "schema_version {schema_version}"
            )));
        }

        let run = value.get("run").ok_or_else(|| field("missing run"))?;
        let events_node = value
            .get("events")
            .and_then(Value::as_array)
            .ok_or_else(|| field("missing events"))?;
        let mut events = Vec::with_capacity(events_node.len());
        for item in events_node {
            let proof = item
                .get("inclusion_proof")
                .ok_or_else(|| field("inclusion_proof"))?;
            events.push(ReceiptEvent {
                canonical: bytes_of(item, "canonical_b64")?,
                leaf_index: u64::try_from(int_of(proof, "leaf_index")?)
                    .map_err(|_| field("leaf_index"))?,
                tree_size: u64::try_from(int_of(proof, "tree_size")?)
                    .map_err(|_| field("tree_size"))?,
                path: path_of(proof, "path")?,
            });
        }

        let checkpoints_node = value
            .get("checkpoints")
            .and_then(Value::as_array)
            .ok_or_else(|| field("missing checkpoints"))?;
        let checkpoints = checkpoints_node
            .iter()
            .map(checkpoint_of)
            .collect::<Result<Vec<_>>>()?;

        let policy = value.get("policy").ok_or_else(|| field("missing policy"))?;

        let global_log = match value.get("global_log") {
            None => None,
            Some(node) => {
                let proof = node
                    .get("inclusion_proof")
                    .ok_or_else(|| field("global proof"))?;
                let chain = node
                    .get("checkpoints")
                    .and_then(Value::as_array)
                    .ok_or_else(|| field("global checkpoints"))?;
                Some(GlobalInclusion {
                    record: bytes_of(node, "record_b64")?,
                    leaf_index: u64::try_from(int_of(proof, "leaf_index")?)
                        .map_err(|_| field("global leaf_index"))?,
                    tree_size: u64::try_from(int_of(proof, "tree_size")?)
                        .map_err(|_| field("global tree_size"))?,
                    path: path_of(proof, "path")?,
                    checkpoints: chain
                        .iter()
                        .map(checkpoint_of)
                        .collect::<Result<Vec<_>>>()?,
                })
            }
        };

        let mut manifest_entries = Vec::new();
        if let Some(section) = value.get("artifacts") {
            let items = section
                .get("manifest_entries")
                .and_then(Value::as_array)
                .ok_or_else(|| field("artifacts.manifest_entries"))?;
            for item in items {
                let text = item.as_str().ok_or_else(|| field("manifest entry"))?;
                manifest_entries
                    .push(b64::decode(text).map_err(|_| field("manifest entry is not base64"))?);
            }
        }

        let mut witnesses = Vec::new();
        if let Some(items) = value.get("witnesses").and_then(Value::as_array) {
            for item in items {
                witnesses.push(WitnessRecord {
                    statement_bytes: bytes_of(item, "statement_b64")?,
                    signature: text_of(item, "signature")?,
                });
            }
        }
        let mut anchors = Vec::new();
        if let Some(items) = value.get("anchors").and_then(Value::as_array) {
            for item in items {
                anchors.push(AnchorRecord {
                    checkpoint_hash: text_of(item, "checkpoint_hash")?,
                    tree_size: int_of(item, "tree_size")?,
                    location: text_of(item, "location")?,
                    anchor_domain: text_of(item, "anchor_domain")?,
                    published_at: int_of(item, "published_at")?,
                });
            }
        }

        let mut approvals = Vec::new();
        if let Some(items) = value.get("approvals").and_then(Value::as_array) {
            for item in items {
                approvals.push(ApprovalRecord {
                    statement_bytes: bytes_of(item, "statement_b64")?,
                    key_id: text_of(item, "key_id")?,
                    signature: text_of(item, "signature")?,
                });
            }
        }
        let mandate = match value.get("mandate") {
            Some(node) => Some(MandateRecord {
                document_bytes: bytes_of(node, "document_b64")?,
                signature: text_of(node, "signature")?,
            }),
            None => None,
        };
        let mut disclosures = Vec::new();
        if let Some(items) = value.get("disclosures").and_then(Value::as_array) {
            for item in items {
                disclosures.push(DisclosureRecord {
                    event_id: text_of(item, "event_id")?,
                    field: text_of(item, "field")?,
                    salt_hex: text_of(item, "salt_hex")?,
                    value: item
                        .get("value")
                        .cloned()
                        .ok_or_else(|| field("disclosure value"))?,
                });
            }
        }

        let timestamps = value
            .get("timestamps")
            .ok_or_else(|| field("missing timestamps"))?;
        let export = value.get("export").ok_or_else(|| field("missing export"))?;

        Ok(Self {
            protocol_version,
            schema_version,
            run_id: text_of(run, "run_id")?,
            adapter_name: text_of(run, "adapter_name")?,
            adapter_version: text_of(run, "adapter_version")?,
            declared_coverage: text_of(run, "declared_coverage")?,
            observed_coverage: text_of(run, "observed_coverage")?,
            profile: text_of(run, "profile")?,
            events,
            checkpoints,
            policy_id: text_of(policy, "policy_id")?,
            policy_version: int_of(policy, "policy_version")?,
            global_log,
            key_manifest_ref: text_of(
                value.get("key_manifest_ref").unwrap_or(&Value::Null),
                "location",
            )
            .unwrap_or_else(|_| "unstated".to_owned()),
            exporter: text_of(export, "exporter").unwrap_or_else(|_| "unstated".to_owned()),
            timestamps_claimed: text_of(timestamps, "label")
                .map(|label| label == "claimed")
                .unwrap_or(true),
            manifest_entries,
            witnesses,
            anchors,
            approvals,
            mandate,
            disclosures,
        })
    }
}

// --------------------------------------------------------------------------- //
// verification
// --------------------------------------------------------------------------- //

/// Verify a receipt and return the full report.
///
/// `keys` comes from a channel independent of the receipt (`PROTOCOL.md` 10.5).
/// Without it, signatures cannot be judged and the relevant dimensions report
/// `UNKNOWN` rather than passing.
#[must_use]
pub fn verify(receipt: &Receipt, keys: Option<&KeyManifest>, profile: Profile) -> Report {
    verify_with(receipt, keys, profile, &[])
}

/// Like [`verify`], with the artifact files that travelled in the container.
///
/// `artifacts` is `(digest, bytes)` pairs. A receipt that lists manifest
/// entries but ships no bytes is still checkable for chain integrity;
/// availability is then `UNKNOWN`, not `PASS`.
#[must_use]
pub fn verify_with(
    receipt: &Receipt,
    keys: Option<&KeyManifest>,
    profile: Profile,
    artifacts: &[(String, Vec<u8>)],
) -> Report {
    let shape = ReceiptShape {
        artifacts_present: !receipt.manifest_entries.is_empty(),
        mandate_present: run_declares_mandate(receipt),
    };
    let mut report = Report::new(profile, shape);

    check_events(receipt, &mut report);
    check_checkpoints(receipt, keys, &mut report);
    check_global_log(receipt, keys, &mut report);
    check_coverage(receipt, &mut report);
    check_policy(receipt, &mut report);
    check_approvals(receipt, keys, &mut report);
    check_disclosures(receipt, &mut report);
    check_outcome(receipt, &mut report);

    check_artifacts(receipt, artifacts, &mut report);
    check_mandate(receipt, keys, &mut report);
    // Advisory channels: read their records if there are any; no record is UNKNOWN.
    check_semantic(receipt, &mut report);
    check_prompt_security(receipt, &mut report);
    check_anomaly(receipt, &mut report);
    for dim in [Dimension::MlAssessment] {
        if report.status(dim) == Status::Unknown {
            report.note(dim, None, "no records of this kind in the receipt");
        }
    }
    check_witnesses(receipt, keys, profile, &mut report);
    check_anchors(receipt, keys, profile, &mut report);

    report
}

/// Parse every event once, for the checks that read event contents.
fn parsed_events(receipt: &Receipt) -> Vec<Option<abb_event::ValidatedEvent>> {
    receipt
        .events
        .iter()
        .map(|event| abb_event::validate(&event.canonical).ok())
        .collect()
}

/// Manifest chain, manifest head against the signed checkpoint, and the bytes.
///
/// A matching digest proves the bytes are the ones that were committed. It does
/// not prove the capture is genuine or the page truthful (`R-ART-07`).
fn check_artifacts(receipt: &Receipt, files: &[(String, Vec<u8>)], report: &mut Report) {
    use manifest::{artifact_digest, check_chain, parse_entry};

    let checkpoint = receipt.checkpoints.last();

    if receipt.manifest_entries.is_empty() {
        // No artifact section. That is only "not applicable" if the signed
        // checkpoint also says the manifest is empty; otherwise artifacts were
        // removed from the receipt and the signed head gives it away.
        let claimed = checkpoint.map_or(0, |c| c.payload.manifest_size);
        if claimed == 0 {
            report.set(Dimension::ArtifactManifestIntegrity, Status::NotApplicable);
            report.set(Dimension::ArtifactAvailability, Status::NotApplicable);
        } else {
            report.fail(
                Dimension::ArtifactManifestIntegrity,
                None,
                format!(
                    "the signed checkpoint commits to {claimed} artifact(s) but the receipt \
                     carries none: the manifest was removed"
                ),
            );
            report.set(Dimension::ArtifactAvailability, Status::Unknown);
        }
        return;
    }

    let mut entries = Vec::new();
    let mut ok = true;
    for (position, bytes) in receipt.manifest_entries.iter().enumerate() {
        match parse_entry(bytes) {
            Ok(entry) => entries.push(entry),
            Err(why) => {
                report.fail(
                    Dimension::ArtifactManifestIntegrity,
                    Some(format!("manifest entry at position {position}")),
                    why.to_string(),
                );
                ok = false;
            }
        }
    }
    if !ok {
        report.set(Dimension::ArtifactAvailability, Status::Unknown);
        return;
    }

    match check_chain(&entries, &receipt.run_id) {
        Err(why) => {
            report.fail(Dimension::ArtifactManifestIntegrity, None, why.to_string());
            ok = false;
        }
        Ok((size, head)) => {
            // The head is what binds the manifest to a signed value.
            match checkpoint {
                None => {
                    report.set(Dimension::ArtifactManifestIntegrity, Status::Unknown);
                    report.note(
                        Dimension::ArtifactManifestIntegrity,
                        None,
                        "no checkpoint to bind the manifest head to",
                    );
                    ok = false;
                }
                Some(checkpoint) => {
                    if checkpoint.payload.manifest_head != head
                        || checkpoint.payload.manifest_size != size
                    {
                        report.fail(
                            Dimension::ArtifactManifestIntegrity,
                            None,
                            format!(
                                "the manifest in this receipt ends at {head} ({size} entries) \
                                 but the signed checkpoint commits to {} ({} entries)",
                                checkpoint.payload.manifest_head, checkpoint.payload.manifest_size
                            ),
                        );
                        ok = false;
                    }
                }
            }
        }
    }
    if ok {
        report.set(Dimension::ArtifactManifestIntegrity, Status::Pass);
    }

    // The bytes themselves.
    let mut missing = 0usize;
    let mut bad = false;
    for entry in &entries {
        match files
            .iter()
            .find(|(name, _)| *name == entry.artifact_digest)
        {
            None => missing += 1,
            Some((_, bytes)) => {
                if artifact_digest(bytes) != entry.artifact_digest {
                    report.fail(
                        Dimension::ArtifactManifestIntegrity,
                        Some(format!("artifact {}", entry.artifact_digest)),
                        "the artifact bytes do not match the digest the manifest committed to: \
                         the file was swapped or damaged",
                    );
                    bad = true;
                } else if i64::try_from(bytes.len()).unwrap_or(-1) != entry.size {
                    report.fail(
                        Dimension::ArtifactManifestIntegrity,
                        Some(format!("artifact {}", entry.artifact_digest)),
                        "the artifact size does not match the manifest",
                    );
                    bad = true;
                }
            }
        }
    }
    if bad {
        report.set(Dimension::ArtifactAvailability, Status::Fail);
    } else if missing == 0 {
        report.set(Dimension::ArtifactAvailability, Status::Pass);
    } else {
        report.set(Dimension::ArtifactAvailability, Status::Unknown);
        report.note(
            Dimension::ArtifactAvailability,
            None,
            format!(
                "{missing} of {} artifact file(s) were not shipped with the receipt, so \
                 their bytes were not checked",
                entries.len()
            ),
        );
    }
}

/// The signer's `failure_domain` from the key manifest, if it names one.
fn signer_domain(receipt: &Receipt, keys: Option<&KeyManifest>) -> Option<String> {
    let key_id = &receipt.checkpoints.last()?.payload.key_id;
    keys?.get(key_id)?.failure_domain.clone()
}

/// Witness quorum (`PROTOCOL.md` 12, `D-02`, `D-15`).
///
/// `PASS` needs at least two valid signatures from witnesses whose
/// `failure_domain` differs from each other **and** from the signer's. Same
/// machine or same administrator gives `NOT_INDEPENDENT`, never `PASS`. A
/// signature that is present but does not verify is `FAIL`.
fn check_witnesses(
    receipt: &Receipt,
    keys: Option<&KeyManifest>,
    profile: Profile,
    report: &mut Report,
) {
    if receipt.witnesses.is_empty() {
        // "NOT_APPLICABLE means no witnesses are configured" (12). Under
        // CONNECTED_EVIDENCE witnesses are required, so their absence is
        // missing evidence, which is UNKNOWN and never a pass.
        if profile == Profile::ConnectedEvidence {
            report.set(Dimension::WitnessQuorum, Status::Unknown);
            report.note(
                Dimension::WitnessQuorum,
                None,
                "this profile requires witnesses and the receipt carries none",
            );
        } else {
            report.set(Dimension::WitnessQuorum, Status::NotApplicable);
        }
        return;
    }
    let Some(final_global) = receipt
        .global_log
        .as_ref()
        .and_then(|g| g.checkpoints.last())
    else {
        report.set(Dimension::WitnessQuorum, Status::Unknown);
        report.note(
            Dimension::WitnessQuorum,
            None,
            "witnesses sign a global checkpoint and none is present",
        );
        return;
    };
    let Some(manifest) = keys else {
        report.set(Dimension::WitnessQuorum, Status::Unknown);
        report.note(
            Dimension::WitnessQuorum,
            None,
            "no key manifest was supplied, so witness signatures were not checked",
        );
        return;
    };
    let target = final_global
        .payload
        .checkpoint_hash_hex()
        .unwrap_or_default();
    let signer = signer_domain(receipt, keys);

    let mut valid: Vec<(String, String)> = Vec::new(); // (witness_id, domain)
    let mut failed = false;
    for (position, record) in receipt.witnesses.iter().enumerate() {
        let locator = Some(format!("witness at position {position}"));
        let text = std::str::from_utf8(&record.statement_bytes).unwrap_or_default();
        let statement = match abb_checkpoint::WitnessStatement::from_canonical(text) {
            Ok(statement) => statement,
            Err(why) => {
                report.fail(
                    Dimension::WitnessQuorum,
                    locator,
                    format!("unreadable statement: {why}"),
                );
                failed = true;
                continue;
            }
        };
        if statement.stream_id != "global" || statement.checkpoint_hash != target {
            report.fail(
                Dimension::WitnessQuorum,
                locator,
                "this witness signed a different checkpoint than the receipt's final global one",
            );
            failed = true;
            continue;
        }
        let entry = match manifest.require_any(&statement.witness_id, Role::Witness) {
            Ok(entry) => entry,
            Err(why) => {
                report.fail(
                    Dimension::WitnessQuorum,
                    locator,
                    format!("witness key: {why}"),
                );
                failed = true;
                continue;
            }
        };
        // The domain the witness signed must be the one the manifest records,
        // or the label means nothing.
        if entry.failure_domain.as_deref() != Some(statement.failure_domain.as_str()) {
            report.fail(
                Dimension::WitnessQuorum,
                locator,
                "the failure domain in the statement differs from the key manifest's",
            );
            failed = true;
            continue;
        }
        match entry
            .verifying_key()
            .and_then(|k| statement.verify(&record.signature, &k))
        {
            Ok(()) => valid.push((
                statement.witness_id.clone(),
                statement.failure_domain.clone(),
            )),
            Err(why) => {
                report.fail(
                    Dimension::WitnessQuorum,
                    locator,
                    format!("signature did not verify: {why}"),
                );
                failed = true;
            }
        }
    }
    if failed {
        return;
    }

    // Count witnesses that are independent of each other and of the signer.
    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut independent = 0usize;
    for (_, domain) in &valid {
        let distinct = !domains.contains(domain);
        let apart_from_signer = signer.as_deref().is_some_and(|s| s != domain);
        if distinct && apart_from_signer {
            independent += 1;
        }
        domains.insert(domain.clone());
    }
    if independent >= 2 {
        report.set(Dimension::WitnessQuorum, Status::Pass);
        report.note(
            Dimension::WitnessQuorum,
            None,
            format!("{independent} witnesses from distinct failure domains, apart from the signer"),
        );
    } else if valid.len() > independent {
        report.set(Dimension::WitnessQuorum, Status::NotIndependent);
        report.note(
            Dimension::WitnessQuorum,
            None,
            "a valid witness shares a failure domain with the signer or with another witness, \
             so it does not count as independent",
        );
    } else {
        report.set(Dimension::WitnessQuorum, Status::Unknown);
        report.note(
            Dimension::WitnessQuorum,
            None,
            format!("{independent} independent witness(es) of the 2 the quorum needs"),
        );
    }
}

/// Anchors (`PROTOCOL.md` 13): a checkpoint digest published outside the system.
fn check_anchors(
    receipt: &Receipt,
    keys: Option<&KeyManifest>,
    profile: Profile,
    report: &mut Report,
) {
    if receipt.anchors.is_empty() {
        if profile == Profile::ConnectedEvidence {
            report.set(Dimension::AnchorMatch, Status::Unknown);
            report.note(
                Dimension::AnchorMatch,
                None,
                "this profile requires an anchor and the receipt carries none",
            );
        } else {
            report.set(Dimension::AnchorMatch, Status::NotApplicable);
        }
        return;
    }
    let Some(global) = receipt.global_log.as_ref() else {
        report.set(Dimension::AnchorMatch, Status::Unknown);
        report.note(
            Dimension::AnchorMatch,
            None,
            "an anchor covers a global checkpoint and none is present",
        );
        return;
    };
    let our_size = global.checkpoints.last().map_or(0, |c| c.payload.tree_size);
    let signer = signer_domain(receipt, keys);

    let mut failed = false;
    let mut matched = false;
    let mut shared_domain = false;
    for anchor in &receipt.anchors {
        let locator = Some(anchor.location.clone());
        if anchor.tree_size > our_size {
            report.fail(
                Dimension::AnchorMatch,
                locator,
                format!(
                    "the anchor covers {} runs but this receipt's global log has {our_size}",
                    anchor.tree_size
                ),
            );
            failed = true;
            continue;
        }
        let same_size = global
            .checkpoints
            .iter()
            .find(|c| c.payload.tree_size == anchor.tree_size);
        match same_size {
            None => {
                report.note(
                    Dimension::AnchorMatch,
                    locator,
                    "the receipt has no global checkpoint at the anchored size to compare with",
                );
            }
            Some(checkpoint) => {
                let ours = checkpoint.payload.checkpoint_hash_hex().unwrap_or_default();
                if ours != anchor.checkpoint_hash {
                    report.fail(
                        Dimension::AnchorMatch,
                        locator,
                        format!(
                            "ANCHOR_MISMATCH: the anchor published {} for size {} but this \
                             receipt's checkpoint hashes to {ours}",
                            anchor.checkpoint_hash, anchor.tree_size
                        ),
                    );
                    failed = true;
                } else {
                    matched = true;
                    if signer.as_deref() == Some(anchor.anchor_domain.as_str()) {
                        shared_domain = true;
                    }
                }
            }
        }
    }
    if failed {
        return;
    }
    if !matched {
        report.set(Dimension::AnchorMatch, Status::Unknown);
    } else if shared_domain || signer.is_none() {
        report.set(Dimension::AnchorMatch, Status::NotIndependent);
        report.note(
            Dimension::AnchorMatch,
            None,
            "the anchor matches, but it is published under the signer's own administrative \
             domain, so it is not an independent record (D-15). A Git commit time is not a \
             trusted timestamp either",
        );
    } else {
        report.set(Dimension::AnchorMatch, Status::Pass);
    }
}

fn check_events(receipt: &Receipt, report: &mut Report) {
    if receipt.events.is_empty() {
        report.set(Dimension::EvidenceIntegrity, Status::Unknown);
        report.note(
            Dimension::EvidenceIntegrity,
            None,
            "the receipt carries no events",
        );
        return;
    }
    let Some(final_checkpoint) = receipt.checkpoints.last() else {
        report.set(Dimension::EvidenceIntegrity, Status::Unknown);
        report.note(
            Dimension::EvidenceIntegrity,
            None,
            "no checkpoint to check events against",
        );
        return;
    };
    let Ok(expected_root) = as_hash(&final_checkpoint.payload.root_hash) else {
        report.fail(
            Dimension::EvidenceIntegrity,
            None,
            "the checkpoint root is not a digest",
        );
        return;
    };

    // The receipt's own event set, for the summary below.
    let leaves: Vec<Vec<u8>> = receipt
        .events
        .iter()
        .map(|event| tagged_bytes(tags::EVENT, &event.canonical))
        .collect();
    let receipt_root = abb_merkle::mth(&leaves);

    // Inclusion failures are collected, not reported as they happen. How many
    // there are decides what is useful to say:
    //
    //  * a few  -> name each one. Their proofs come from the signed tree, so a
    //              failure means *that* event's bytes were changed. This is
    //              what "the verifier names the broken point" means.
    //  * all    -> the proofs were regenerated from altered data, so naming
    //              every event would bury the single fact that matters.
    let mut inclusion_failures: Vec<(String, String)> = Vec::new();

    let mut ok = true;
    let mut previous_sequence: Option<i64> = None;

    for (position, event) in receipt.events.iter().enumerate() {
        let locator = format!("event at position {position}");

        // The bytes must be exactly canonical and a well-formed envelope,
        // otherwise "the leaf hash matches" would mean nothing.
        let validated = match abb_event::validate(&event.canonical) {
            Ok(validated) => validated,
            Err(why) => {
                report.fail(
                    Dimension::EvidenceIntegrity,
                    Some(locator.clone()),
                    format!("not a valid canonical event: {why}"),
                );
                ok = false;
                continue;
            }
        };

        if validated.run_id != receipt.run_id {
            report.fail(
                Dimension::EvidenceIntegrity,
                Some(format!("event {}", validated.event_id)),
                "belongs to another run",
            );
            ok = false;
        }
        match previous_sequence {
            None if validated.sequence != 0 => {
                report.fail(
                    Dimension::EvidenceIntegrity,
                    Some(locator.clone()),
                    format!(
                        "the first event has sequence {}, expected 0",
                        validated.sequence
                    ),
                );
                ok = false;
            }
            Some(previous) if validated.sequence != previous + 1 => {
                report.fail(
                    Dimension::EvidenceIntegrity,
                    Some(format!("event {}", validated.event_id)),
                    format!(
                        "sequence {} does not follow {previous}: the history has a gap, a \
                         repeat or a reordering",
                        validated.sequence
                    ),
                );
                ok = false;
            }
            _ => {}
        }
        previous_sequence = Some(validated.sequence);

        // The leaf hash and its inclusion proof.
        let leaf = leaf_hash(&tagged_bytes(tags::EVENT, &event.canonical));
        if event.leaf_index != u64::try_from(validated.sequence).unwrap_or(u64::MAX) {
            report.fail(
                Dimension::EvidenceIntegrity,
                Some(format!("event {}", validated.event_id)),
                "the proof's leaf index does not match the event's sequence",
            );
            ok = false;
        }
        match verify_inclusion(&leaf, event.leaf_index, event.tree_size, &event.path) {
            Err(why) => {
                report.fail(
                    Dimension::EvidenceIntegrity,
                    Some(format!("event {}", validated.event_id)),
                    format!("inclusion proof rejected: {why}"),
                );
                ok = false;
            }
            Ok(derived) => {
                if derived != expected_root {
                    inclusion_failures.push((
                        format!(
                            "event {} (sequence {})",
                            validated.event_id, validated.sequence
                        ),
                        hex_lower(&derived),
                    ));
                    ok = false;
                }
            }
        }
    }

    // Now say the useful thing about the inclusion failures.
    if !inclusion_failures.is_empty() {
        if inclusion_failures.len() == receipt.events.len() && receipt.events.len() > 1 {
            report.fail(
                Dimension::EvidenceIntegrity,
                None,
                format!(
                    "none of the {} events in this receipt is in the signed tree: they hash \
                     to {} but the signed checkpoint says {}. The receipt was rebuilt from \
                     data that had already been changed",
                    receipt.events.len(),
                    hex_lower(&receipt_root),
                    hex_lower(&expected_root)
                ),
            );
        } else {
            for (locator, derived) in &inclusion_failures {
                report.fail(
                    Dimension::EvidenceIntegrity,
                    Some(locator.clone()),
                    format!(
                        "this event is not in the signed tree: its proof derives {derived} \
                         but the checkpoint says {}. Its recorded bytes have been changed",
                        hex_lower(&expected_root)
                    ),
                );
            }
        }
    }

    // The tree must cover exactly the events the receipt carries.
    let covered = final_checkpoint.payload.tree_size;
    if covered != i64::try_from(receipt.events.len()).unwrap_or(i64::MAX) {
        report.fail(
            Dimension::EvidenceIntegrity,
            None,
            format!(
                "the final checkpoint covers {covered} events but the receipt carries {}: \
                 the history has been truncated or padded",
                receipt.events.len()
            ),
        );
        ok = false;
    }

    if ok {
        report.set(Dimension::EvidenceIntegrity, Status::Pass);
    }
}

fn check_checkpoints(receipt: &Receipt, keys: Option<&KeyManifest>, report: &mut Report) {
    if receipt.checkpoints.is_empty() {
        report.set(Dimension::CheckpointSignatures, Status::Unknown);
        report.set(Dimension::Consistency, Status::Unknown);
        report.note(
            Dimension::CheckpointSignatures,
            None,
            "the receipt carries no checkpoints",
        );
        return;
    }

    // Signatures.
    match keys {
        None => {
            report.set(Dimension::CheckpointSignatures, Status::Unknown);
            report.note(
                Dimension::CheckpointSignatures,
                None,
                "no key manifest was supplied, so signatures were not checked",
            );
        }
        Some(manifest) => {
            let mut ok = true;
            for checkpoint in &receipt.checkpoints {
                let locator = checkpoint.payload.checkpoint_hash_hex().ok();
                match manifest.require(&checkpoint.payload.key_id, Role::Signer) {
                    Err(why) => {
                        report.fail(
                            Dimension::CheckpointSignatures,
                            locator,
                            format!("key {}: {why}", checkpoint.payload.key_id),
                        );
                        ok = false;
                    }
                    Ok(entry) => match entry.verifying_key() {
                        Err(why) => {
                            report.fail(
                                Dimension::CheckpointSignatures,
                                locator,
                                format!("unusable key: {why}"),
                            );
                            ok = false;
                        }
                        Ok(verifying) => {
                            if let Err(why) =
                                checkpoint.payload.verify(&checkpoint.signature, &verifying)
                            {
                                report.fail(
                                    Dimension::CheckpointSignatures,
                                    locator,
                                    format!("signature did not verify: {why}"),
                                );
                                ok = false;
                            }
                        }
                    },
                }
            }
            if ok {
                report.set(Dimension::CheckpointSignatures, Status::Pass);
            }
        }
    }

    // The chain and its consistency proofs.
    let mut ok = true;
    let mut previous: Option<&ReceiptCheckpoint> = None;
    for checkpoint in &receipt.checkpoints {
        if checkpoint.payload.stream_id != receipt.run_id {
            report.fail(
                Dimension::Consistency,
                None,
                "a checkpoint belongs to another stream",
            );
            ok = false;
        }
        match previous {
            None => {
                if !checkpoint.payload.is_genesis_shaped() {
                    report.fail(
                        Dimension::Consistency,
                        None,
                        "the first checkpoint is not a genesis: its previous hash is not zero",
                    );
                    ok = false;
                }
            }
            Some(earlier) => {
                let expected = earlier.payload.checkpoint_hash_hex().unwrap_or_default();
                if checkpoint.payload.prev_checkpoint_hash != expected {
                    report.fail(
                        Dimension::Consistency,
                        checkpoint.payload.checkpoint_hash_hex().ok(),
                        "this checkpoint does not link to the previous one",
                    );
                    ok = false;
                }
                if checkpoint.payload.tree_size < earlier.payload.tree_size {
                    report.fail(
                        Dimension::Consistency,
                        None,
                        "a later checkpoint covers fewer events than an earlier one",
                    );
                    ok = false;
                }
                // The consistency proof, which is what makes "it only grew" checkable.
                let (Ok(first_root), Ok(second_root)) = (
                    as_hash(&earlier.payload.root_hash),
                    as_hash(&checkpoint.payload.root_hash),
                ) else {
                    report.fail(
                        Dimension::Consistency,
                        None,
                        "a checkpoint root is not a digest",
                    );
                    ok = false;
                    continue;
                };
                let first_size = u64::try_from(earlier.payload.tree_size).unwrap_or(0);
                let second_size = u64::try_from(checkpoint.payload.tree_size).unwrap_or(0);
                match verify_consistency(
                    first_size,
                    second_size,
                    &first_root,
                    &checkpoint.consistency_from_previous,
                ) {
                    Err(why) => {
                        report.fail(
                            Dimension::Consistency,
                            checkpoint.payload.checkpoint_hash_hex().ok(),
                            format!("consistency proof rejected: {why}"),
                        );
                        ok = false;
                    }
                    Ok(derived) if derived != second_root => {
                        report.fail(
                            Dimension::Consistency,
                            checkpoint.payload.checkpoint_hash_hex().ok(),
                            "the consistency proof does not reach this checkpoint's root",
                        );
                        ok = false;
                    }
                    Ok(_) => {}
                }
            }
        }
        previous = Some(checkpoint);
    }
    if ok {
        report.set(Dimension::Consistency, Status::Pass);
    }
}

fn check_global_log(receipt: &Receipt, keys: Option<&KeyManifest>, report: &mut Report) {
    let Some(global) = &receipt.global_log else {
        report.set(Dimension::GlobalLogInclusion, Status::Unknown);
        report.note(
            Dimension::GlobalLogInclusion,
            None,
            "the receipt carries no global-log inclusion, so a deleted run could not be \
             detected from it (D-10)",
        );
        return;
    };
    let Some(final_global) = global.checkpoints.last() else {
        report.set(Dimension::GlobalLogInclusion, Status::Unknown);
        report.note(Dimension::GlobalLogInclusion, None, "no global checkpoint");
        return;
    };

    let mut ok = true;

    // The record must describe this run and the run's own final checkpoint.
    let record_text = std::str::from_utf8(&global.record).unwrap_or_default();
    let record = abb_jcs::parse(record_text).ok();
    match (&record, receipt.checkpoints.last()) {
        (Some(record), Some(run_final)) => {
            let claimed = record
                .get("run_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if claimed != receipt.run_id {
                report.fail(
                    Dimension::GlobalLogInclusion,
                    None,
                    "the global record names another run",
                );
                ok = false;
            }
            let expected = run_final.payload.checkpoint_hash_hex().unwrap_or_default();
            let named = record
                .get("checkpoint_hash")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if named != expected {
                report.fail(
                    Dimension::GlobalLogInclusion,
                    None,
                    "the global record does not name this run's final checkpoint",
                );
                ok = false;
            }
        }
        _ => {
            report.fail(
                Dimension::GlobalLogInclusion,
                None,
                "the global record is unreadable",
            );
            ok = false;
        }
    }

    // Its inclusion in the global tree.
    let leaf = leaf_hash(&tagged_bytes(tags::RUNROOT, &global.record));
    let Ok(global_root) = as_hash(&final_global.payload.root_hash) else {
        report.fail(
            Dimension::GlobalLogInclusion,
            None,
            "the global root is not a digest",
        );
        return;
    };
    match verify_inclusion(&leaf, global.leaf_index, global.tree_size, &global.path) {
        Err(why) => {
            report.fail(
                Dimension::GlobalLogInclusion,
                None,
                format!("global inclusion proof rejected: {why}"),
            );
            ok = false;
        }
        Ok(derived) if derived != global_root => {
            report.fail(
                Dimension::GlobalLogInclusion,
                None,
                "this run is not in the signed global log",
            );
            ok = false;
        }
        Ok(_) => {}
    }

    if final_global.payload.stream_id != "global" {
        report.fail(
            Dimension::GlobalLogInclusion,
            None,
            "the global checkpoint is not the global stream",
        );
        ok = false;
    }

    // And the global checkpoint must itself be signed by the signer.
    if let Some(manifest) = keys {
        for checkpoint in &global.checkpoints {
            match manifest
                .require(&checkpoint.payload.key_id, Role::Signer)
                .and_then(|entry| entry.verifying_key())
            {
                Err(why) => {
                    report.fail(
                        Dimension::GlobalLogInclusion,
                        None,
                        format!("global checkpoint key: {why}"),
                    );
                    ok = false;
                }
                Ok(verifying) => {
                    if let Err(why) = checkpoint.payload.verify(&checkpoint.signature, &verifying) {
                        report.fail(
                            Dimension::GlobalLogInclusion,
                            None,
                            format!("global checkpoint signature did not verify: {why}"),
                        );
                        ok = false;
                    }
                }
            }
        }
    }

    if ok {
        report.set(Dimension::GlobalLogInclusion, Status::Pass);
        report.note(
            Dimension::GlobalLogInclusion,
            None,
            "the run is in the global log. Whether the log itself was rolled back is a \
             separate question, answered by witnesses and anchors",
        );
    }
}

/// Coverage honesty (`PROTOCOL.md` 7, `D-14`, `R-COV-07`).
/// What the run's own signed events say about coverage: the declared level from
/// the last `COVERAGE_DECLARED`, and the lowest `observed_coverage` any event's
/// provenance carries. A receipt header must agree with these, because a header
/// is not signed and the events are.
pub fn coverage_from_events<'a>(
    canonical_events: impl IntoIterator<Item = &'a [u8]>,
) -> (Option<String>, Option<String>) {
    let rank = |level: &str| match level {
        "TASK_LEVEL" => Some(0),
        "STEP_OBSERVED" => Some(1),
        "STEP_GATED" => Some(2),
        _ => None,
    };
    let mut declared: Option<String> = None;
    let mut observed: Option<(i32, String)> = None;
    for bytes in canonical_events {
        let Ok(value) = abb_jcs::parse(std::str::from_utf8(bytes).unwrap_or("{}")) else {
            continue;
        };
        if value.get("event_type").and_then(Value::as_str) == Some("COVERAGE_DECLARED") {
            if let Some(level) = value
                .get("payload")
                .and_then(|p| p.get("declared_coverage"))
                .and_then(Value::as_str)
            {
                declared = Some(level.to_owned());
            }
        }
        if let Some(level) = value
            .get("provenance")
            .and_then(|p| p.get("observed_coverage"))
            .and_then(Value::as_str)
        {
            if let Some(r) = rank(level) {
                if observed.as_ref().is_none_or(|(low, _)| r < *low) {
                    observed = Some((r, level.to_owned()));
                }
            }
        }
    }
    (declared, observed.map(|(_, level)| level))
}

fn check_coverage(receipt: &Receipt, report: &mut Report) {
    let events = parsed_events(receipt);
    let mut ok = true;

    // The header is not signed; the events are. Judge the claim the events make.
    let (declared_events, observed_events) =
        coverage_from_events(receipt.events.iter().map(|e| e.canonical.as_slice()));
    let Some(declared) = declared_events else {
        report.set(Dimension::ObservationCoverage, Status::Unknown);
        report.note(
            Dimension::ObservationCoverage,
            None,
            "no event declares the run's coverage, so the header's claim has nothing behind it",
        );
        return;
    };
    let observed = observed_events.unwrap_or_else(|| receipt.observed_coverage.clone());
    if declared != receipt.declared_coverage || observed != receipt.observed_coverage {
        report.fail(
            Dimension::ObservationCoverage,
            None,
            format!(
                "the receipt header says declared {} / observed {}, but the signed events say \
                 declared {declared} / observed {observed}",
                receipt.declared_coverage, receipt.observed_coverage
            ),
        );
        ok = false;
    }

    // Declared coverage may not exceed what the adapter evidenced.
    let rank = |level: &str| match level {
        "TASK_LEVEL" => 0,
        "STEP_OBSERVED" => 1,
        "STEP_GATED" => 2,
        _ => -1,
    };
    if rank(&declared) < 0 {
        report.fail(
            Dimension::ObservationCoverage,
            None,
            "unknown declared coverage",
        );
        ok = false;
    }
    if rank(&declared) > rank(&observed) {
        report.fail(
            Dimension::ObservationCoverage,
            None,
            format!("declared {} but only {} was observed", declared, observed),
        );
        ok = false;
    }

    // A LIVE_EXTERNAL stream is capped at STEP_OBSERVED without recorded
    // capability evidence (D-14).
    let external = events.iter().flatten().any(|_| false); // provenance.mode is inside the payload; checked below
    let _ = external;
    let mut modes: BTreeSet<String> = BTreeSet::new();
    for event in &receipt.events {
        if let Ok(value) = abb_jcs::parse(std::str::from_utf8(&event.canonical).unwrap_or("{}")) {
            if let Some(mode) = value
                .get("provenance")
                .and_then(|p| p.get("mode"))
                .and_then(Value::as_str)
            {
                modes.insert(mode.to_owned());
            }
        }
    }
    if modes.contains("LIVE_EXTERNAL") && declared == "STEP_GATED" {
        report.fail(
            Dimension::ObservationCoverage,
            None,
            "a LIVE_EXTERNAL run cannot declare STEP_GATED without recorded capability \
             evidence (D-14)",
        );
        ok = false;
    }

    // For STEP_GATED, every dispatch needs an earlier authorization for the
    // same action (R-COV-07). This is the check that makes the label mean
    // something.
    if declared == "STEP_GATED" {
        let mut authorized: BTreeSet<String> = BTreeSet::new();
        for (position, event) in receipt.events.iter().enumerate() {
            let Ok(value) = abb_jcs::parse(std::str::from_utf8(&event.canonical).unwrap_or("{}"))
            else {
                continue;
            };
            let event_type = value
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let action_id = value
                .get("payload")
                .and_then(|p| p.get("action_id"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            match event_type {
                "ACTION_AUTHORIZED" => {
                    authorized.insert(action_id);
                }
                "ACTION_DISPATCHED" => {
                    if !authorized.contains(&action_id) {
                        report.fail(
                            Dimension::ObservationCoverage,
                            Some(format!("event at position {position}")),
                            format!(
                                "action {action_id} was dispatched with no earlier \
                                 authorization, so this run is not STEP_GATED"
                            ),
                        );
                        ok = false;
                    }
                }
                _ => {}
            }
        }
    }

    if ok {
        report.set(Dimension::ObservationCoverage, Status::Pass);
        report.note(
            Dimension::ObservationCoverage,
            None,
            match declared.as_str() {
                "STEP_GATED" => {
                    "gated actions were policy-checked before execution, within \
                                 the declared boundary"
                }
                "STEP_OBSERVED" => {
                    "observed steps were recorded; not every action is \
                                    necessarily intercepted"
                }
                _ => "task-level reporting only",
            },
        );
    }
}

/// The deterministic policy channel (`PROTOCOL.md` 14).
fn check_policy(receipt: &Receipt, report: &mut Report) {
    let mut requested: BTreeMap<String, bool> = BTreeMap::new();
    let mut violations = 0usize;
    let mut decisions = 0usize;

    for event in &receipt.events {
        let Ok(value) = abb_jcs::parse(std::str::from_utf8(&event.canonical).unwrap_or("{}"))
        else {
            continue;
        };
        let event_type = value
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let payload = value.get("payload");
        let action_id = payload
            .and_then(|p| p.get("action_id"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        match event_type {
            "ACTION_REQUESTED" => {
                requested.entry(action_id).or_insert(false);
            }
            "ACTION_AUTHORIZED" | "ACTION_BLOCKED" => {
                decisions += 1;
                requested.insert(action_id, true);
                // Every decision must name the policy that made it.
                let named = payload
                    .and_then(|p| p.get("policy_id"))
                    .and_then(Value::as_str);
                if named != Some(receipt.policy_id.as_str()) {
                    report.fail(
                        Dimension::PolicyAssessment,
                        None,
                        "a decision names a different policy than the run declares",
                    );
                }
            }
            "POLICY_VIOLATION_DETECTED" => violations += 1,
            _ => {}
        }
    }

    let undecided: Vec<&String> = requested
        .iter()
        .filter(|(_, decided)| !**decided)
        .map(|(id, _)| id)
        .collect();
    if !undecided.is_empty() {
        report.fail(
            Dimension::PolicyAssessment,
            None,
            format!(
                "{} action(s) were requested with no recorded decision: {}",
                undecided.len(),
                undecided
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
        return;
    }
    if violations > 0 {
        report.fail(
            Dimension::PolicyAssessment,
            None,
            format!("{violations} recorded policy violation(s)"),
        );
        return;
    }
    if report.status(Dimension::PolicyAssessment) != Status::Fail {
        report.set(Dimension::PolicyAssessment, Status::Pass);
        report.note(
            Dimension::PolicyAssessment,
            None,
            format!(
                "{decisions} deterministic decision(s) under policy {} v{}",
                receipt.policy_id, receipt.policy_version
            ),
        );
    }
}

/// What the run said about itself. Informational: never changes the result.
fn check_outcome(receipt: &Receipt, report: &mut Report) {
    for event in &receipt.events {
        let Ok(value) = abb_jcs::parse(std::str::from_utf8(&event.canonical).unwrap_or("{}"))
        else {
            continue;
        };
        if value.get("event_type").and_then(Value::as_str) == Some("RUN_FINISHED") {
            let outcome = value
                .get("payload")
                .and_then(|p| p.get("outcome"))
                .and_then(Value::as_str)
                .unwrap_or("unstated");
            report.set(Dimension::ExecutionOutcome, Status::Pass);
            report.note(
                Dimension::ExecutionOutcome,
                None,
                format!(
                    "the run reported {outcome}. This is the run's own claim, not evidence \
                     that anything happened"
                ),
            );
            return;
        }
    }
    report.set(Dimension::ExecutionOutcome, Status::Unknown);
    report.note(
        Dimension::ExecutionOutcome,
        None,
        "the run never recorded RUN_FINISHED, so its outcome is unknown",
    );
}

/// A one-line summary for a person, with the honest caveat attached.
#[must_use]
pub fn summarize(report: &Report) -> String {
    let overall = report.overall();
    let caveat = match overall {
        Overall::Valid => {
            "The signed history is unaltered relative to its checkpoints. That is not a \
             statement that the task was safe, correct, authorized or actually executed."
        }
        Overall::Invalid => "Something that must hold does not. See the named point above.",
        Overall::Incomplete => "Something the profile requires is missing, so this is not a pass.",
        Overall::Partial => "Everything required holds; something optional is missing.",
        Overall::Unsupported => "This build cannot judge that receipt.",
    };
    format!("{overall}\n{caveat}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_receipt_is_incomplete_not_valid() {
        let report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        assert_eq!(report.overall(), Overall::Incomplete);
    }

    #[test]
    fn the_summary_never_overclaims() {
        let mut report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        for dim in Dimension::ALL {
            report.set(dim, Status::Pass);
        }
        let text = summarize(&report);
        assert!(text.starts_with("VALID"));
        assert!(text.contains("not a statement that the task was safe"));
    }

    #[test]
    fn a_receipt_with_an_unknown_version_is_unsupported() {
        let bytes = br#"{"protocol_version":"abb/2","schema_version":1}"#;
        assert!(matches!(
            Receipt::parse(bytes),
            Err(ReceiptError::Unsupported(_))
        ));
        let bytes = br#"{"protocol_version":"abb/1","schema_version":9}"#;
        assert!(matches!(
            Receipt::parse(bytes),
            Err(ReceiptError::Unsupported(_))
        ));
    }

    #[test]
    fn malformed_input_is_a_result_not_a_panic() {
        for bad in [b"".as_slice(), b"{", b"[]", b"null", b"{\"a\":1.5}"] {
            let _ = Receipt::parse(bad);
        }
    }
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use abb_verify::{Profile, ReceiptShape};

    fn event(kind: &str, payload: &str, observed: &str) -> ReceiptEvent {
        let text = format!(
            r#"{{"event_id":"e","event_type":"{kind}","created_at":1,"sequence":1,"payload":{payload},"provenance":{{"adapter_name":"a","adapter_version":"1","execution_id":"x","mode":"REPLAY","observed_coverage":"{observed}"}}}}"#
        );
        let canonical = abb_jcs::to_canonical(&abb_jcs::parse(&text).unwrap()).unwrap();
        ReceiptEvent {
            canonical: canonical.into_bytes(),
            leaf_index: 0,
            tree_size: 0,
            path: Vec::new(),
        }
    }

    fn declaration(level: &str, observed: &str) -> ReceiptEvent {
        event(
            "COVERAGE_DECLARED",
            &format!(
                r#"{{"requested_coverage":"STEP_GATED","declared_coverage":"{level}","in_scope_actions":[],"reason":"t"}}"#
            ),
            observed,
        )
    }

    fn receipt(header_declared: &str, header_observed: &str, events: Vec<ReceiptEvent>) -> Receipt {
        Receipt {
            declared_coverage: header_declared.to_owned(),
            observed_coverage: header_observed.to_owned(),
            events,
            ..Receipt::default()
        }
    }

    fn judge(r: &Receipt) -> (Status, String) {
        let mut report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        check_coverage(r, &mut report);
        let text = report
            .details
            .iter()
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(" | ");
        (report.status(Dimension::ObservationCoverage), text)
    }

    #[test]
    fn the_declared_level_is_the_last_declaration_and_observed_is_the_lowest() {
        let events = [
            declaration("STEP_GATED", "STEP_GATED"),
            declaration("STEP_OBSERVED", "STEP_OBSERVED"),
            event("ACTION_REQUESTED", "{}", "STEP_GATED"),
        ];
        let bytes: Vec<&[u8]> = events.iter().map(|e| e.canonical.as_slice()).collect();
        let (declared, observed) = coverage_from_events(bytes);
        assert_eq!(declared.as_deref(), Some("STEP_OBSERVED"));
        assert_eq!(observed.as_deref(), Some("STEP_OBSERVED"));
    }

    #[test]
    fn a_header_that_agrees_with_the_events_passes() {
        let r = receipt(
            "STEP_OBSERVED",
            "STEP_OBSERVED",
            vec![declaration("STEP_OBSERVED", "STEP_OBSERVED")],
        );
        assert_eq!(judge(&r).0, Status::Pass);
    }

    #[test]
    fn a_header_that_claims_more_than_the_events_declared_fails() {
        // The run said STEP_OBSERVED; the unsigned header says STEP_GATED.
        let r = receipt(
            "STEP_GATED",
            "STEP_OBSERVED",
            vec![declaration("STEP_OBSERVED", "STEP_OBSERVED")],
        );
        let (status, text) = judge(&r);
        assert_eq!(status, Status::Fail);
        assert!(text.contains("signed events say"), "{text}");
    }

    #[test]
    fn a_header_that_inflates_what_was_observed_fails() {
        let r = receipt(
            "STEP_OBSERVED",
            "STEP_GATED",
            vec![declaration("STEP_OBSERVED", "STEP_OBSERVED")],
        );
        assert_eq!(judge(&r).0, Status::Fail);
    }

    #[test]
    fn declaring_gated_when_only_observation_was_evidenced_fails() {
        let r = receipt(
            "STEP_GATED",
            "STEP_OBSERVED",
            vec![declaration("STEP_GATED", "STEP_OBSERVED")],
        );
        let (status, text) = judge(&r);
        assert_eq!(status, Status::Fail);
        assert!(text.contains("only STEP_OBSERVED was observed"), "{text}");
    }

    #[test]
    fn no_declaration_event_is_unknown_never_pass() {
        let r = receipt(
            "STEP_GATED",
            "STEP_GATED",
            vec![event("RUN_STARTED", "{}", "STEP_GATED")],
        );
        let (status, text) = judge(&r);
        assert_eq!(status, Status::Unknown);
        assert!(text.contains("nothing behind it"), "{text}");
    }
}
