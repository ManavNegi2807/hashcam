//! Building a receipt from an export bundle.
//!
//! The split is deliberate. The service knows the database; it writes a
//! **bundle**: the canonical event bytes, the checkpoints the signer returned,
//! and the global-log records. This module knows the protocol; it computes
//! every proof, lays out `receipt.json` canonically and writes the container.
//!
//! So the service never computes a hash or a proof, and this code never touches
//! a database (`AGENTS.md` 3.10, `R-PRO-04`).

use abb_checkpoint::{tagged_bytes, tags, CheckpointPayload};
use abb_jcs::{b64, hex_lower, Limits, Value};
use abb_merkle::{consistency_path, inclusion_path, mth};

use crate::{field, ReceiptError, ReceiptFile, Result, SCHEMA_VERSION};

/// Build `receipt.json` and the container from a bundle.
///
/// The bundle is ordinary JSON, in any key order: it is the service's
/// hand-off, not a signed document.
pub fn build(bundle_bytes: &[u8]) -> Result<ReceiptFile> {
    let bundle = abb_jcs::parse_bytes(bundle_bytes, &Limits::relaxed())
        .map_err(|e| ReceiptError::Unreadable(format!("bundle: {e}")))?;

    let run = bundle.get("run").ok_or_else(|| field("bundle.run"))?;
    let events = decode_list(&bundle, "events")?;
    if events.is_empty() {
        return Err(field("a receipt needs at least one event"));
    }
    let (declared_from_events, observed_from_events) =
        crate::coverage_from_events(events.iter().map(Vec::as_slice));

    // Event leaves, and the tree they form.
    let leaves: Vec<Vec<u8>> = events
        .iter()
        .map(|bytes| tagged_bytes(tags::EVENT, bytes))
        .collect();
    let root = hex_lower(&mth(&leaves));

    // Checkpoints, in order, with a consistency proof from the one before.
    let checkpoint_nodes = bundle
        .get("checkpoints")
        .and_then(Value::as_array)
        .ok_or_else(|| field("bundle.checkpoints"))?;
    if checkpoint_nodes.is_empty() {
        return Err(field("a receipt needs at least one checkpoint"));
    }
    let mut checkpoints = Vec::with_capacity(checkpoint_nodes.len());
    let mut previous_size: Option<usize> = None;
    for node in checkpoint_nodes {
        let payload_bytes = b64::decode(&text(node, "payload_b64")?)
            .map_err(|_| field("checkpoint payload_b64"))?;
        let text_payload =
            std::str::from_utf8(&payload_bytes).map_err(|_| field("checkpoint payload"))?;
        let payload = CheckpointPayload::from_canonical(text_payload)
            .map_err(|e| field(format!("checkpoint payload: {e}")))?;
        let size = usize::try_from(payload.tree_size).map_err(|_| field("tree_size"))?;
        if size > leaves.len() {
            return Err(field(format!(
                "a checkpoint covers {size} events but the bundle carries {}",
                leaves.len()
            )));
        }
        let proof = match previous_size {
            None => Vec::new(),
            Some(first) => consistency_path(first, &leaves[..size])
                .map_err(|e| field(format!("consistency proof: {e}")))?,
        };
        let mut entries = vec![
            (
                "payload_b64".to_owned(),
                Value::Str(b64::encode(&payload_bytes)),
            ),
            ("signature".to_owned(), Value::Str(text(node, "signature")?)),
        ];
        if !proof.is_empty() {
            entries.push((
                "consistency_from_previous".to_owned(),
                Value::Array(proof.iter().map(|h| Value::Str(hex_lower(h))).collect()),
            ));
        }
        checkpoints.push(Value::Object(entries));
        previous_size = Some(size);
    }

    // The final checkpoint is what the event proofs are against.
    let final_size = previous_size.unwrap_or(0);
    if final_size != leaves.len() {
        return Err(field(format!(
            "the final checkpoint covers {final_size} events but the bundle carries {}: \
             finalize before exporting",
            leaves.len()
        )));
    }

    let mut event_nodes = Vec::with_capacity(events.len());
    for (index, bytes) in events.iter().enumerate() {
        let path = inclusion_path(index, &leaves)
            .map_err(|e| field(format!("inclusion proof for event {index}: {e}")))?;
        event_nodes.push(Value::Object(vec![
            ("canonical_b64".to_owned(), Value::Str(b64::encode(bytes))),
            (
                "inclusion_proof".to_owned(),
                Value::Object(vec![
                    (
                        "leaf_index".to_owned(),
                        Value::Int(i64::try_from(index).unwrap_or(0)),
                    ),
                    (
                        "tree_size".to_owned(),
                        Value::Int(i64::try_from(leaves.len()).unwrap_or(0)),
                    ),
                    (
                        "path".to_owned(),
                        Value::Array(path.iter().map(|h| Value::Str(hex_lower(h))).collect()),
                    ),
                ]),
            ),
        ]));
    }

    // The global log (D-10): the run's record, its proof, and the chain.
    let global_log = match bundle.get("global") {
        None => None,
        Some(global) => {
            let records = decode_list(global, "records")?;
            let position = usize::try_from(
                global
                    .get("position")
                    .and_then(Value::as_int)
                    .ok_or_else(|| field("position"))?,
            )
            .map_err(|_| field("position"))?;
            let global_leaves: Vec<Vec<u8>> = records
                .iter()
                .map(|r| tagged_bytes(tags::RUNROOT, r))
                .collect();
            let record = records
                .get(position)
                .ok_or_else(|| field("position is past the global records"))?
                .clone();
            let path = inclusion_path(position, &global_leaves)
                .map_err(|e| field(format!("global inclusion proof: {e}")))?;
            let chain = global
                .get("checkpoints")
                .and_then(Value::as_array)
                .ok_or_else(|| field("global.checkpoints"))?;
            let mut chain_nodes = Vec::with_capacity(chain.len());
            for node in chain {
                chain_nodes.push(Value::Object(vec![
                    (
                        "payload_b64".to_owned(),
                        Value::Str(text(node, "payload_b64")?),
                    ),
                    ("signature".to_owned(), Value::Str(text(node, "signature")?)),
                ]));
            }
            Some(Value::Object(vec![
                ("record_b64".to_owned(), Value::Str(b64::encode(&record))),
                (
                    "inclusion_proof".to_owned(),
                    Value::Object(vec![
                        (
                            "leaf_index".to_owned(),
                            Value::Int(i64::try_from(position).unwrap_or(0)),
                        ),
                        (
                            "tree_size".to_owned(),
                            Value::Int(i64::try_from(global_leaves.len()).unwrap_or(0)),
                        ),
                        (
                            "path".to_owned(),
                            Value::Array(path.iter().map(|h| Value::Str(hex_lower(h))).collect()),
                        ),
                    ]),
                ),
                ("checkpoints".to_owned(), Value::Array(chain_nodes)),
            ]))
        }
    };

    let policy = bundle.get("policy").ok_or_else(|| field("bundle.policy"))?;

    // Artifact manifest entries (Step 6). Optional: a run may capture nothing.
    let manifest_entries = match bundle.get("manifest_entries") {
        None => Vec::new(),
        Some(_) => decode_list(&bundle, "manifest_entries")?,
    };
    let mut artifact_files: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(items) = bundle.get("artifacts").and_then(Value::as_array) {
        for item in items {
            let digest = text(item, "digest")?;
            let bytes =
                b64::decode(&text(item, "bytes_b64")?).map_err(|_| field("artifact bytes_b64"))?;
            artifact_files.push((digest, bytes));
        }
    }

    let mut receipt = vec![
        (
            "protocol_version".to_owned(),
            Value::Str(abb_checkpoint::PROTOCOL_VERSION.to_owned()),
        ),
        ("schema_version".to_owned(), Value::Int(SCHEMA_VERSION)),
        (
            "run".to_owned(),
            Value::Object(vec![
                ("run_id".to_owned(), Value::Str(text(run, "run_id")?)),
                (
                    "adapter_name".to_owned(),
                    Value::Str(text(run, "adapter_name")?),
                ),
                (
                    "adapter_version".to_owned(),
                    Value::Str(text(run, "adapter_version")?),
                ),
                // Coverage comes from what the signed events say, not from a
                // database column: the exporter's own opinion is not evidence.
                (
                    "declared_coverage".to_owned(),
                    Value::Str(match &declared_from_events {
                        Some(level) => level.clone(),
                        None => text(run, "declared_coverage")?,
                    }),
                ),
                (
                    "observed_coverage".to_owned(),
                    Value::Str(match &observed_from_events {
                        Some(level) => level.clone(),
                        None => text(run, "observed_coverage")?,
                    }),
                ),
                ("profile".to_owned(), Value::Str(text(run, "profile")?)),
                ("root_hash".to_owned(), Value::Str(root)),
            ]),
        ),
        ("events".to_owned(), Value::Array(event_nodes)),
        ("checkpoints".to_owned(), Value::Array(checkpoints)),
        (
            "policy".to_owned(),
            Value::Object(vec![
                (
                    "policy_id".to_owned(),
                    Value::Str(text(policy, "policy_id")?),
                ),
                (
                    "policy_version".to_owned(),
                    Value::Int(
                        policy
                            .get("policy_version")
                            .and_then(Value::as_int)
                            .ok_or_else(|| field("policy_version"))?,
                    ),
                ),
                (
                    "body_digest".to_owned(),
                    Value::Str(text(policy, "body_digest")?),
                ),
            ]),
        ),
        (
            "key_manifest_ref".to_owned(),
            Value::Object(vec![(
                "location".to_owned(),
                Value::Str(
                    bundle
                        .get("key_manifest_ref")
                        .and_then(Value::as_str)
                        .unwrap_or("published out of band")
                        .to_owned(),
                ),
            )]),
        ),
        (
            // Timestamps are claims unless trusted-timestamp evidence is
            // attached, and none is (PROTOCOL.md 10.4).
            "timestamps".to_owned(),
            Value::Object(vec![
                ("label".to_owned(), Value::Str("claimed".to_owned())),
                (
                    "note".to_owned(),
                    Value::Str(
                        "every time in this receipt is a local clock reading, not evidence"
                            .to_owned(),
                    ),
                ),
            ]),
        ),
        (
            "export".to_owned(),
            Value::Object(vec![
                (
                    "exporter".to_owned(),
                    Value::Str("abb receipt build".to_owned()),
                ),
                (
                    "version".to_owned(),
                    Value::Str(env!("CARGO_PKG_VERSION").to_owned()),
                ),
                (
                    "exported_at".to_owned(),
                    Value::Int(
                        bundle
                            .get("exported_at")
                            .and_then(Value::as_int)
                            .unwrap_or_default(),
                    ),
                ),
            ]),
        ),
    ];
    if let Some(global) = global_log {
        receipt.push(("global_log".to_owned(), global));
    }
    // Witness signatures and anchor publications are out-of-band evidence the
    // service gathered; the builder carries them verbatim and the verifier
    // judges them. It adds nothing of its own.
    if let Some(items) = bundle.get("witnesses").and_then(Value::as_array) {
        if !items.is_empty() {
            receipt.push(("witnesses".to_owned(), Value::Array(items.to_vec())));
        }
    }
    // Signed approvals, the mandate and chosen disclosures are likewise carried
    // verbatim: the exporter never signs or judges them.
    if let Some(items) = bundle.get("approvals").and_then(Value::as_array) {
        if !items.is_empty() {
            receipt.push(("approvals".to_owned(), Value::Array(items.to_vec())));
        }
    }
    if let Some(node) = bundle.get("mandate") {
        if !matches!(node, Value::Null) {
            receipt.push(("mandate".to_owned(), node.clone()));
        }
    }
    if let Some(items) = bundle.get("disclosures").and_then(Value::as_array) {
        if !items.is_empty() {
            receipt.push(("disclosures".to_owned(), Value::Array(items.to_vec())));
        }
    }
    if let Some(items) = bundle.get("anchors").and_then(Value::as_array) {
        if !items.is_empty() {
            receipt.push(("anchors".to_owned(), Value::Array(items.to_vec())));
        }
    }
    if !manifest_entries.is_empty() {
        receipt.push((
            "artifacts".to_owned(),
            Value::Object(vec![(
                "manifest_entries".to_owned(),
                Value::Array(
                    manifest_entries
                        .iter()
                        .map(|e| Value::Str(b64::encode(e)))
                        .collect(),
                ),
            )]),
        ));
    }

    let receipt_json = abb_jcs::to_canonical_with(&Value::Object(receipt), &Limits::relaxed())
        .map_err(|e| field(format!("cannot canonicalize the receipt: {e}")))?;

    Ok(ReceiptFile {
        receipt_json: receipt_json.into_bytes(),
        artifacts: artifact_files,
    })
}

fn text(node: &Value, name: &str) -> Result<String> {
    node.get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| field(format!("missing {name}")))
}

fn decode_list(node: &Value, name: &str) -> Result<Vec<Vec<u8>>> {
    let items = node
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| field(format!("missing {name}")))?;
    items
        .iter()
        .map(|item| {
            let text = item
                .as_str()
                .ok_or_else(|| field(format!("{name} must be base64")))?;
            b64::decode(text).map_err(|_| field(format!("{name} is not base64")))
        })
        .collect()
}
