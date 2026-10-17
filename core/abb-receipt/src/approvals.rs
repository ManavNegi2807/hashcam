//! Offline checks for signed approvals, the signed mandate and disclosed fields
//! (`PROTOCOL.md` 5.5, 5.6, 5.7; decisions D-11 and D-16).
//!
//! The rule that shapes everything here: **a gateway that marks its own
//! homework proves nothing**. So the verifier re-derives from the events and
//! the signed statements alone whether a human allowed an action and whether
//! the run stayed inside its mandate. It does not trust a `GRANTED` event just
//! because the control plane wrote it: the approver's own signature, made with
//! a key the control plane does not hold, has to check out against the key
//! manifest.
//!
//! A valid signature proves that a key signed, not which person held it.

use std::collections::{BTreeMap, BTreeSet};

use abb_checkpoint::{field_commitment, ApprovalStatement, KeyManifest, Mandate, Role, SALT_LEN};
use abb_jcs::{hex_decode, Value};
use abb_verify::{Dimension, Report, Status};

use crate::Receipt;

/// One approver signature as a receipt carries it.
#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    /// The exact signed statement bytes.
    pub statement_bytes: Vec<u8>,
    /// The approver's key id.
    pub key_id: String,
    /// Hex signature.
    pub signature: String,
}

/// The signed mandate as a receipt carries it.
#[derive(Debug, Clone)]
pub struct MandateRecord {
    /// The exact mandate document bytes.
    pub document_bytes: Vec<u8>,
    /// Hex signature.
    pub signature: String,
}

/// A field the exporter chose to reveal (`PROTOCOL.md` 5.5).
#[derive(Debug, Clone)]
pub struct DisclosureRecord {
    /// The event the field belongs to.
    pub event_id: String,
    /// The field name.
    pub field: String,
    /// The salt, as lowercase hex.
    pub salt_hex: String,
    /// The clear value.
    pub value: Value,
}

struct Ev {
    sequence: i64,
    event_type: String,
    event_id: String,
    created_at: i64,
    payload: Value,
    commitments: Option<Value>,
}

fn events_of(receipt: &Receipt) -> Vec<Ev> {
    let mut out = Vec::new();
    for event in &receipt.events {
        let Ok(text) = std::str::from_utf8(&event.canonical) else {
            continue;
        };
        let Ok(value) = abb_jcs::parse(text) else {
            continue;
        };
        out.push(Ev {
            sequence: value.get("sequence").and_then(Value::as_int).unwrap_or(-1),
            event_type: value
                .get("event_type")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            event_id: value
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            created_at: value
                .get("created_at")
                .and_then(Value::as_int)
                .unwrap_or_default(),
            payload: value.get("payload").cloned().unwrap_or(Value::Null),
            commitments: value.get("commitments").cloned(),
        });
    }
    out
}

fn pstr<'a>(payload: &'a Value, name: &str) -> &'a str {
    payload
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// True when `RUN_STARTED` declared a mandate. Decides whether the
/// `mandate_compliance` dimension is required (`PROTOCOL.md` 16.1).
#[must_use]
pub fn run_declares_mandate(receipt: &Receipt) -> bool {
    events_of(receipt)
        .iter()
        .any(|e| e.event_type == "RUN_STARTED" && e.payload.get("mandate_digest").is_some())
}

// --------------------------------------------------------------------------- //
// approvals
// --------------------------------------------------------------------------- //

/// Check every approval event and every gated dispatch. Writes to
/// `policy_assessment`: a missing or invalid approval makes it `FAIL`
/// (`PROTOCOL.md` 5.6); one that cannot be checked for lack of a key manifest
/// makes it `UNKNOWN`, never `PASS`.
pub fn check_approvals(receipt: &Receipt, keys: Option<&KeyManifest>, report: &mut Report) {
    let events = events_of(receipt);
    let dim = Dimension::PolicyAssessment;

    // approval_id -> (action_id, summary_digest) from the request events.
    let mut requested: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut needs_approval: BTreeSet<String> = BTreeSet::new();
    // action_id -> expires_at of a verified grant seen so far.
    let mut granted: BTreeMap<String, i64> = BTreeMap::new();
    let mut denied: BTreeSet<String> = BTreeSet::new();
    let mut unverifiable = 0usize;
    let mut checked = 0usize;

    for ev in &events {
        let locator = Some(format!("event {} (sequence {})", ev.event_id, ev.sequence));
        match ev.event_type.as_str() {
            "HUMAN_APPROVAL_REQUESTED" => {
                let action_id = pstr(&ev.payload, "action_id").to_owned();
                requested.insert(
                    pstr(&ev.payload, "approval_id").to_owned(),
                    (
                        action_id.clone(),
                        pstr(&ev.payload, "summary_digest").to_owned(),
                    ),
                );
                needs_approval.insert(action_id);
            }
            "HUMAN_APPROVAL_GRANTED" | "HUMAN_APPROVAL_DENIED" => {
                let granted_event = ev.event_type == "HUMAN_APPROVAL_GRANTED";
                let approval_id = pstr(&ev.payload, "approval_id");
                let action_id = pstr(&ev.payload, "action_id");
                let Some((req_action, req_digest)) = requested.get(approval_id) else {
                    report.fail(
                        dim,
                        locator,
                        "an approval decision has no matching approval request before it",
                    );
                    continue;
                };
                if req_action != action_id {
                    report.fail(
                        dim,
                        locator,
                        "APPROVAL_MISMATCH: the decision names a different action than the request",
                    );
                    continue;
                }
                let Some(record) = receipt.approvals.iter().find(|r| {
                    std::str::from_utf8(&r.statement_bytes)
                        .ok()
                        .and_then(|t| ApprovalStatement::from_canonical(t).ok())
                        .is_some_and(|s| s.approval_id == approval_id)
                }) else {
                    report.fail(
                        dim,
                        locator,
                        "an approval decision has no signed statement: the control plane's word alone \
                         is not an approval",
                    );
                    continue;
                };
                let Some(manifest) = keys else {
                    unverifiable += 1;
                    report.note(
                        dim,
                        locator,
                        "no key manifest was supplied, so the approver's signature was not checked",
                    );
                    continue;
                };
                checked += 1;
                let statement = match std::str::from_utf8(&record.statement_bytes)
                    .map_err(|_| "not text".to_owned())
                    .and_then(|t| ApprovalStatement::from_canonical(t).map_err(|e| e.to_string()))
                {
                    Ok(s) => s,
                    Err(why) => {
                        report.fail(
                            dim,
                            locator,
                            format!("unreadable approval statement: {why}"),
                        );
                        continue;
                    }
                };
                let entry = match manifest.require(&record.key_id, Role::Approver) {
                    Ok(entry) => entry,
                    Err(why) => {
                        report.fail(
                            dim,
                            locator,
                            format!(
                                "the approver key is not an active approver in the manifest: {why}"
                            ),
                        );
                        continue;
                    }
                };
                let verified = entry
                    .verifying_key()
                    .and_then(|key| statement.verify(&record.signature, &key));
                if verified.is_err() {
                    report.fail(
                        dim,
                        locator,
                        "the approval signature does not verify against the approver key",
                    );
                    continue;
                }
                if pstr(&ev.payload, "approver_key_id") != record.key_id {
                    report.fail(
                        dim,
                        locator,
                        "the event names a different approver key than the one that signed",
                    );
                    continue;
                }
                if statement.run_id != receipt.run_id {
                    report.fail(dim, locator, "the approval was signed for a different run");
                    continue;
                }
                if statement.action_id != action_id {
                    report.fail(
                        dim,
                        locator,
                        "APPROVAL_MISMATCH: the signed statement is for a different action",
                    );
                    continue;
                }
                if &statement.summary_digest != req_digest {
                    report.fail(
                        dim,
                        locator,
                        "APPROVAL_MISMATCH: the approver signed a different summary than the one requested",
                    );
                    continue;
                }
                let decision_matches = (statement.decision == "GRANTED") == granted_event;
                if !decision_matches {
                    report.fail(
                        dim,
                        locator,
                        "the event and the signed statement disagree on granted versus denied",
                    );
                    continue;
                }
                if granted_event {
                    if ev.payload.get("expires_at").and_then(Value::as_int)
                        != Some(statement.expires_at)
                    {
                        report.fail(
                            dim,
                            locator,
                            "the event's expires_at differs from the signed expires_at",
                        );
                        continue;
                    }
                    granted.insert(action_id.to_owned(), statement.expires_at);
                } else {
                    denied.insert(action_id.to_owned());
                }
            }
            "ACTION_DISPATCHED" => {
                let action_id = pstr(&ev.payload, "action_id");
                if !needs_approval.contains(action_id) {
                    continue;
                }
                if denied.contains(action_id) {
                    report.fail(
                        dim,
                        locator,
                        "an action was dispatched after a signed denial",
                    );
                } else if let Some(expires) = granted.get(action_id) {
                    if ev.created_at > *expires {
                        report.fail(
                            dim,
                            locator,
                            "APPROVAL_EXPIRED: dispatched after the approval's expires_at \
                             (both times are claims)",
                        );
                    }
                } else if unverifiable == 0 {
                    report.fail(
                        dim,
                        locator,
                        "APPROVAL_REQUIRED: an action that needed approval was dispatched without a \
                         verified grant",
                    );
                }
            }
            _ => {}
        }
    }

    if unverifiable > 0 && report.status(dim) == Status::Pass {
        report.set(dim, Status::Unknown);
    }
    if checked > 0 && report.status(dim) == Status::Pass {
        report.note(
            dim,
            None,
            format!(
                "{checked} approval signature(s) verified against approver keys in the manifest; a \
                 signature shows a key signed, not which person held it"
            ),
        );
    }
}

// --------------------------------------------------------------------------- //
// mandate
// --------------------------------------------------------------------------- //

/// The host of an `http` or `https` URL, lowercased, without port or userinfo.
fn host_of(target: &str) -> Option<String> {
    let (scheme, rest) = target.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next()?
    } else {
        host_port.split(':').next()?
    };
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Check the signed mandate and that every dispatched action stayed inside it.
///
/// Blocked or merely proposed actions are not violations: a mandate that
/// stopped an out-of-bounds proposal worked. What fails is a *dispatch* that
/// was outside it, because that means the gateway did not enforce it.
pub fn check_mandate(receipt: &Receipt, keys: Option<&KeyManifest>, report: &mut Report) {
    let dim = Dimension::MandateCompliance;
    let events = events_of(receipt);
    let Some(started) = events
        .iter()
        .find(|e| e.event_type == "RUN_STARTED" && e.payload.get("mandate_digest").is_some())
    else {
        report.set(dim, Status::NotApplicable);
        return;
    };

    let Some(record) = &receipt.mandate else {
        report.set(dim, Status::Unknown);
        report.note(
            dim,
            None,
            "the run declared a mandate but the receipt does not carry the mandate document",
        );
        return;
    };
    let Some(manifest) = keys else {
        report.set(dim, Status::Unknown);
        report.note(
            dim,
            None,
            "no key manifest was supplied, so the mandate signature was not checked",
        );
        return;
    };
    let mandate = match std::str::from_utf8(&record.document_bytes)
        .map_err(|_| "not text".to_owned())
        .and_then(|t| Mandate::from_canonical(t).map_err(|e| e.to_string()))
    {
        Ok(m) => m,
        Err(why) => {
            report.fail(dim, None, format!("unreadable mandate: {why}"));
            return;
        }
    };

    let mut bad = false;
    let mut fail = |report: &mut Report, locator: Option<String>, message: String| {
        report.fail(dim, locator, message);
        bad = true;
    };

    match mandate.digest_hex() {
        Ok(digest) if digest == pstr(&started.payload, "mandate_digest") => {}
        _ => fail(
            report,
            None,
            "the mandate document does not match the digest RUN_STARTED committed to".to_owned(),
        ),
    }
    if mandate.issuer_key_id != pstr(&started.payload, "mandate_issuer_key_id") {
        fail(
            report,
            None,
            "the mandate names a different issuer than RUN_STARTED".to_owned(),
        );
    }
    if record.signature != pstr(&started.payload, "mandate_signature") {
        fail(
            report,
            None,
            "the mandate signature differs from the one RUN_STARTED committed to".to_owned(),
        );
    }
    match manifest.require(&mandate.issuer_key_id, Role::MandateIssuer) {
        Ok(entry) => {
            let ok = entry
                .verifying_key()
                .and_then(|key| mandate.verify(&record.signature, &key))
                .is_ok();
            if !ok {
                fail(
                    report,
                    None,
                    "the mandate signature does not verify against the issuer key".to_owned(),
                );
            }
        }
        Err(why) => fail(
            report,
            None,
            format!("the issuer is not an active mandate_issuer in the manifest: {why}"),
        ),
    }
    if mandate.subject != receipt.adapter_name {
        fail(
            report,
            None,
            format!(
                "the mandate is for subject '{}' but the run used '{}'",
                mandate.subject, receipt.adapter_name
            ),
        );
    }
    if started.created_at < mandate.not_before || started.created_at > mandate.not_after {
        fail(
            report,
            Some(format!("event {}", started.event_id)),
            "the run started outside the mandate's validity window (both are time claims)"
                .to_owned(),
        );
    }

    // What was asked for, by action id.
    struct Asked {
        action_type: String,
        target: String,
        amount: Option<i64>,
    }
    let mut asked: BTreeMap<String, Asked> = BTreeMap::new();
    for ev in &events {
        if ev.event_type == "ACTION_REQUESTED" {
            asked.insert(
                pstr(&ev.payload, "action_id").to_owned(),
                Asked {
                    action_type: pstr(&ev.payload, "action_type").to_owned(),
                    target: pstr(&ev.payload, "target").to_owned(),
                    amount: ev.payload.get("amount_minor_units").and_then(Value::as_int),
                },
            );
        }
    }

    let mut dispatched = 0i64;
    let mut spent = 0i64;
    for ev in &events {
        if ev.event_type != "ACTION_DISPATCHED" {
            continue;
        }
        let action_id = pstr(&ev.payload, "action_id");
        let locator = Some(format!(
            "action {action_id} (event {}, sequence {})",
            ev.event_id, ev.sequence
        ));
        dispatched += 1;
        let Some(action) = asked.get(action_id) else {
            fail(
                report,
                locator,
                "MANDATE_VIOLATION: dispatched an action that was never requested".to_owned(),
            );
            continue;
        };
        if !mandate.allowed_action_types.contains(&action.action_type) {
            fail(
                report,
                locator.clone(),
                format!(
                    "MANDATE_VIOLATION: action type {} is not allowed",
                    action.action_type
                ),
            );
        }
        match host_of(&action.target) {
            Some(host) if mandate.allows_host(&host) => {}
            Some(host) => fail(
                report,
                locator.clone(),
                format!("MANDATE_VIOLATION: host {host} is not allowed"),
            ),
            None => fail(
                report,
                locator.clone(),
                "MANDATE_VIOLATION: the target is not an http(s) URL".to_owned(),
            ),
        }
        if let Some(amount) = action.amount {
            spent = spent.saturating_add(amount);
        }
        if dispatched > mandate.max_actions {
            fail(
                report,
                locator,
                format!(
                    "MANDATE_VIOLATION: dispatch number {dispatched} is over max_actions {}",
                    mandate.max_actions
                ),
            );
        }
    }
    if let Some(limit) = mandate.max_spend_minor_units {
        if spent > limit {
            fail(
                report,
                None,
                format!("MANDATE_VIOLATION: dispatched spend {spent} is over the limit {limit}"),
            );
        }
    }

    if !bad {
        report.set(dim, Status::Pass);
        report.note(
            dim,
            None,
            format!(
                "{dispatched} dispatched action(s) stayed inside the signed mandate; a mandate is \
                 evidence of the instructions, not enforcement by itself"
            ),
        );
    }
}

// --------------------------------------------------------------------------- //
// disclosures
// --------------------------------------------------------------------------- //

/// Recompute every disclosed commitment, and say what stays hidden.
///
/// A wrong disclosure is tampering, so it fails `evidence_integrity`. A hidden
/// field is *not* a failure: the leaf hash, inclusion proof and signatures stay
/// valid. The fields simply remain unknown, and the report says so.
pub fn check_disclosures(receipt: &Receipt, report: &mut Report) {
    let dim = Dimension::EvidenceIntegrity;
    let events = events_of(receipt);
    let by_id: BTreeMap<&str, &Ev> = events.iter().map(|e| (e.event_id.as_str(), e)).collect();

    let mut committed: BTreeSet<(String, String)> = BTreeSet::new();
    for ev in &events {
        if let Some(entries) = ev.commitments.as_ref().and_then(Value::as_object) {
            for (field, _) in entries {
                committed.insert((ev.event_id.clone(), field.clone()));
            }
        }
    }

    let mut revealed: BTreeSet<(String, String)> = BTreeSet::new();
    let mut salts: BTreeSet<String> = BTreeSet::new();
    for item in &receipt.disclosures {
        let locator = Some(format!(
            "disclosure of {} on event {}",
            item.field, item.event_id
        ));
        let Some(ev) = by_id.get(item.event_id.as_str()) else {
            report.fail(
                dim,
                locator,
                "a disclosure names an event that is not in the receipt",
            );
            continue;
        };
        let Some(expected) = ev
            .commitments
            .as_ref()
            .and_then(|c| c.get(&item.field))
            .and_then(Value::as_str)
        else {
            report.fail(
                dim,
                locator,
                "a disclosure names a field the event never committed to",
            );
            continue;
        };
        let Ok(salt) = hex_decode(&item.salt_hex) else {
            report.fail(dim, locator, "the salt is not lowercase hex");
            continue;
        };
        if salt.len() != SALT_LEN {
            report.fail(dim, locator, "a salt must be exactly 16 bytes");
            continue;
        }
        if !salts.insert(item.salt_hex.clone()) {
            report.fail(
                dim,
                locator,
                "a salt is reused across disclosures: salts must be unique per field per event",
            );
            continue;
        }
        match field_commitment(&salt, &item.value) {
            Ok(actual) if actual == expected => {
                revealed.insert((item.event_id.clone(), item.field.clone()));
            }
            _ => report.fail(
                dim,
                locator,
                "the disclosed value and salt do not reproduce the committed hash",
            ),
        }
    }

    let hidden = committed.difference(&revealed).count();
    if hidden > 0 {
        report.note(
            dim,
            None,
            format!(
                "{hidden} committed field(s) are not disclosed in this receipt; their content is \
                 unknown. The events' hashes and signatures are unaffected"
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction_handles_ports_userinfo_and_paths() {
        assert_eq!(
            host_of("https://Vendor.Example/a/b"),
            Some("vendor.example".into())
        );
        assert_eq!(
            host_of("https://vendor.example:8443/x"),
            Some("vendor.example".into())
        );
        assert_eq!(
            host_of("https://user:pw@vendor.example/x"),
            Some("vendor.example".into())
        );
        assert_eq!(host_of("http://[::1]:8080/"), Some("::1".into()));
        assert_eq!(
            host_of("https://vendor.example?x=1"),
            Some("vendor.example".into())
        );
    }

    #[test]
    fn host_extraction_refuses_what_is_not_a_web_url() {
        assert_eq!(host_of("ftp://vendor.example/"), None);
        assert_eq!(host_of("vendor.example"), None);
        assert_eq!(host_of("https:///path"), None);
        assert_eq!(host_of(""), None);
    }

    #[test]
    fn a_lookalike_host_does_not_pass_through_userinfo() {
        // The part before '@' is userinfo, not the host.
        assert_eq!(
            host_of("https://vendor.example@evil.test/"),
            Some("evil.test".into())
        );
    }
}

#[cfg(test)]
mod verifier_tests {
    use super::*;
    use crate::ReceiptEvent;
    use abb_checkpoint::{key_id_for, tags};
    use abb_jcs::hex_lower;
    use abb_verify::{Profile, ReceiptShape};
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    const RUN: &str = "11111111-1111-4111-8111-111111111111";
    const SUMMARY: &str = "ab";

    fn key(label: &str) -> SigningKey {
        SigningKey::from_bytes(&Sha256::digest(label.as_bytes()).into())
    }

    fn id_of(k: &SigningKey) -> String {
        key_id_for(&k.verifying_key().to_bytes())
    }

    fn manifest(entries: &[(&SigningKey, &str)]) -> KeyManifest {
        let keys = entries
            .iter()
            .map(|(k, role)| {
                format!(
                    r#"{{"key_id":"{}","public_key_hex":"{}","role":"{role}","valid_from":1,"status":"active"}}"#,
                    id_of(k),
                    hex_lower(&k.verifying_key().to_bytes())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let text = format!(r#"{{"keys":[{keys}]}}"#);
        KeyManifest::from_value(&abb_jcs::parse(&text).unwrap()).unwrap()
    }

    fn event(
        seq: i64,
        kind: &str,
        at: i64,
        payload: &str,
        commitments: Option<&str>,
    ) -> ReceiptEvent {
        let extra = commitments
            .map(|c| format!(r#","commitments":{c}"#))
            .unwrap_or_default();
        let text = format!(
            r#"{{"event_id":"e{seq}","event_type":"{kind}","created_at":{at},"sequence":{seq},"payload":{payload}{extra}}}"#
        );
        let canonical = abb_jcs::to_canonical(&abb_jcs::parse(&text).unwrap()).unwrap();
        ReceiptEvent {
            canonical: canonical.into_bytes(),
            leaf_index: 0,
            tree_size: 0,
            path: Vec::new(),
        }
    }

    fn statement(decision: &str, digest: &str, expires: i64) -> ApprovalStatement {
        ApprovalStatement {
            approval_id: "ap1".to_owned(),
            run_id: RUN.to_owned(),
            action_id: "a1".to_owned(),
            summary_digest: digest.repeat(32),
            decision: decision.to_owned(),
            expires_at: expires,
        }
    }

    fn record(
        s: &ApprovalStatement,
        signer: &SigningKey,
        listed_as: &SigningKey,
    ) -> ApprovalRecord {
        ApprovalRecord {
            statement_bytes: abb_jcs::to_canonical(&s.to_value()).unwrap().into_bytes(),
            key_id: id_of(listed_as),
            signature: s.sign(signer).unwrap(),
        }
    }

    /// request, decision, optional dispatch.
    fn approval_run(grant: bool, approver: &SigningKey, dispatch_at: Option<i64>) -> Receipt {
        let mut events = vec![
            event(
                1,
                "ACTION_REQUESTED",
                1000,
                r#"{"action_id":"a1","action_type":"CLICK","target":"https://vendor.example/x"}"#,
                None,
            ),
            event(
                2,
                "HUMAN_APPROVAL_REQUESTED",
                1001,
                &format!(
                    r#"{{"action_id":"a1","approval_id":"ap1","summary_digest":"{}"}}"#,
                    SUMMARY.repeat(32)
                ),
                None,
            ),
        ];
        let payload = if grant {
            format!(
                r#"{{"action_id":"a1","approval_id":"ap1","approver_id":"x","approver_key_id":"{}","expires_at":5000,"approval_signature":"s"}}"#,
                id_of(approver)
            )
        } else {
            format!(
                r#"{{"action_id":"a1","approval_id":"ap1","approver_id":"x","approver_key_id":"{}","reason":"no","approval_signature":"s"}}"#,
                id_of(approver)
            )
        };
        let kind = if grant {
            "HUMAN_APPROVAL_GRANTED"
        } else {
            "HUMAN_APPROVAL_DENIED"
        };
        events.push(event(3, kind, 1002, &payload, None));
        if let Some(at) = dispatch_at {
            events.push(event(
                4,
                "ACTION_DISPATCHED",
                at,
                r#"{"action_id":"a1"}"#,
                None,
            ));
        }
        Receipt {
            run_id: RUN.to_owned(),
            events,
            ..Receipt::default()
        }
    }

    fn fresh_report() -> Report {
        let mut r = Report::new(Profile::LocalOnly, ReceiptShape::default());
        r.set(Dimension::PolicyAssessment, Status::Pass);
        r
    }

    fn run_check(receipt: &Receipt, keys: Option<&KeyManifest>) -> Report {
        let mut report = fresh_report();
        check_approvals(receipt, keys, &mut report);
        report
    }

    fn messages(report: &Report, dim: Dimension) -> String {
        report
            .details
            .iter()
            .filter(|d| d.dimension == dim)
            .map(|d| d.message.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn policy(report: &Report) -> Status {
        report.status(Dimension::PolicyAssessment)
    }

    #[test]
    fn a_valid_signed_grant_gates_dispatch() {
        let a = key("approver");
        let mut r = approval_run(true, &a, Some(2000));
        r.approvals = vec![record(&statement("GRANTED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(
            policy(&report),
            Status::Pass,
            "{}",
            messages(&report, Dimension::PolicyAssessment)
        );
    }

    #[test]
    fn a_forged_signature_fails_policy_assessment() {
        let a = key("approver");
        let forger = key("forger");
        let mut r = approval_run(true, &a, Some(2000));
        // Signed by someone else but presented as the approver's.
        r.approvals = vec![record(&statement("GRANTED", SUMMARY, 5000), &forger, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
        assert!(messages(&report, Dimension::PolicyAssessment).contains("does not verify"));
    }

    #[test]
    fn a_different_summary_is_an_approval_mismatch() {
        let a = key("approver");
        let mut r = approval_run(true, &a, Some(2000));
        r.approvals = vec![record(&statement("GRANTED", "cd", 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
        assert!(messages(&report, Dimension::PolicyAssessment).contains("APPROVAL_MISMATCH"));
    }

    #[test]
    fn dispatch_after_expiry_is_flagged() {
        let a = key("approver");
        let mut r = approval_run(true, &a, Some(5001));
        r.approvals = vec![record(&statement("GRANTED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
        assert!(messages(&report, Dimension::PolicyAssessment).contains("APPROVAL_EXPIRED"));
    }

    #[test]
    fn dispatch_exactly_at_expiry_is_still_inside_it() {
        let a = key("approver");
        let mut r = approval_run(true, &a, Some(5000));
        r.approvals = vec![record(&statement("GRANTED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Pass);
    }

    #[test]
    fn an_approver_key_missing_from_the_manifest_fails() {
        let a = key("approver");
        let other = key("not-listed");
        let mut r = approval_run(true, &a, Some(2000));
        r.approvals = vec![record(&statement("GRANTED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&other, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
    }

    #[test]
    fn a_key_with_the_wrong_role_cannot_approve() {
        let a = key("approver");
        let mut r = approval_run(true, &a, Some(2000));
        r.approvals = vec![record(&statement("GRANTED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "witness")])));
        assert_eq!(policy(&report), Status::Fail);
    }

    #[test]
    fn a_grant_event_with_no_signed_statement_fails() {
        let a = key("approver");
        let r = approval_run(true, &a, Some(2000));
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
        assert!(messages(&report, Dimension::PolicyAssessment).contains("no signed statement"));
    }

    #[test]
    fn dispatch_with_no_decision_at_all_is_approval_required() {
        let a = key("approver");
        let mut r = approval_run(true, &a, None);
        r.events.truncate(2);
        r.events.push(event(
            4,
            "ACTION_DISPATCHED",
            2000,
            r#"{"action_id":"a1"}"#,
            None,
        ));
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
        assert!(messages(&report, Dimension::PolicyAssessment).contains("APPROVAL_REQUIRED"));
    }

    #[test]
    fn dispatch_after_a_signed_denial_fails() {
        let a = key("approver");
        let mut r = approval_run(false, &a, Some(2000));
        r.approvals = vec![record(&statement("DENIED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
        assert!(messages(&report, Dimension::PolicyAssessment).contains("signed denial"));
    }

    #[test]
    fn a_signed_denial_with_no_dispatch_is_fine() {
        let a = key("approver");
        let mut r = approval_run(false, &a, None);
        r.approvals = vec![record(&statement("DENIED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Pass);
    }

    #[test]
    fn without_a_key_manifest_approvals_are_unknown_never_pass() {
        let a = key("approver");
        let mut r = approval_run(true, &a, Some(2000));
        r.approvals = vec![record(&statement("GRANTED", SUMMARY, 5000), &a, &a)];
        let report = run_check(&r, None);
        assert_eq!(policy(&report), Status::Unknown);
    }

    #[test]
    fn a_statement_signed_for_another_run_is_refused() {
        let a = key("approver");
        let mut r = approval_run(true, &a, Some(2000));
        let mut s = statement("GRANTED", SUMMARY, 5000);
        s.run_id = "22222222-2222-4222-8222-222222222222".to_owned();
        r.approvals = vec![record(&s, &a, &a)];
        let report = run_check(&r, Some(&manifest(&[(&a, "approver")])));
        assert_eq!(policy(&report), Status::Fail);
    }

    // ------------------------------------------------------------- mandate

    fn mandate_for(issuer: &SigningKey) -> Mandate {
        Mandate {
            mandate_id: "m1".to_owned(),
            issuer_key_id: id_of(issuer),
            subject: "replay".to_owned(),
            allowed_hosts: vec!["vendor.example".to_owned()],
            allowed_action_types: vec!["CLICK".to_owned()],
            max_actions: 1,
            max_spend_minor_units: Some(100),
            currency: Some("INR".to_owned()),
            not_before: 500,
            not_after: 9000,
        }
    }

    /// Each tuple: action id, target, amount, whether it was dispatched.
    fn mandate_run(
        m: &Mandate,
        issuer: &SigningKey,
        dispatches: &[(&str, &str, Option<i64>, bool)],
    ) -> Receipt {
        let sig = m.sign(issuer).unwrap();
        let started = format!(
            r#"{{"task_digest":"t","adapter":"replay","policy_version":"1","requested_coverage":"STEP_GATED","mandate_digest":"{}","mandate_issuer_key_id":"{}","mandate_signature":"{sig}"}}"#,
            m.digest_hex().unwrap(),
            m.issuer_key_id
        );
        let mut events = vec![event(1, "RUN_STARTED", 1000, &started, None)];
        let mut seq = 2;
        for (id, target, amount, dispatch) in dispatches {
            let amt = amount
                .map(|a| format!(r#","amount_minor_units":{a}"#))
                .unwrap_or_default();
            events.push(event(
                seq,
                "ACTION_REQUESTED",
                1100,
                &format!(
                    r#"{{"action_id":"{id}","action_type":"CLICK","target":"{target}"{amt}}}"#
                ),
                None,
            ));
            seq += 1;
            if *dispatch {
                events.push(event(
                    seq,
                    "ACTION_DISPATCHED",
                    1200,
                    &format!(r#"{{"action_id":"{id}"}}"#),
                    None,
                ));
                seq += 1;
            }
        }
        Receipt {
            run_id: RUN.to_owned(),
            adapter_name: "replay".to_owned(),
            events,
            mandate: Some(MandateRecord {
                document_bytes: abb_jcs::to_canonical(&m.to_value()).unwrap().into_bytes(),
                signature: sig,
            }),
            ..Receipt::default()
        }
    }

    fn mandate_check(r: &Receipt, keys: Option<&KeyManifest>) -> Report {
        let mut report = Report::new(
            Profile::LocalOnly,
            ReceiptShape {
                artifacts_present: false,
                mandate_present: true,
            },
        );
        check_mandate(r, keys, &mut report);
        report
    }

    fn compliance(report: &Report) -> Status {
        report.status(Dimension::MandateCompliance)
    }

    #[test]
    fn no_mandate_means_not_applicable() {
        let mut rep = Report::new(Profile::LocalOnly, ReceiptShape::default());
        check_mandate(&Receipt::default(), None, &mut rep);
        assert_eq!(compliance(&rep), Status::NotApplicable);
    }

    #[test]
    fn a_run_inside_its_mandate_passes() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let r = mandate_run(
            &m,
            &issuer,
            &[("a1", "https://vendor.example/p", Some(50), true)],
        );
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(
            compliance(&report),
            Status::Pass,
            "{}",
            messages(&report, Dimension::MandateCompliance)
        );
    }

    #[test]
    fn a_dispatch_to_an_out_of_mandate_host_fails_and_is_named() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let r = mandate_run(&m, &issuer, &[("a1", "https://evil.test/p", None, true)]);
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(compliance(&report), Status::Fail);
        let text = messages(&report, Dimension::MandateCompliance);
        assert!(
            text.contains("MANDATE_VIOLATION") && text.contains("evil.test"),
            "{text}"
        );
        assert!(report
            .details
            .iter()
            .any(|d| d.locator.as_deref().is_some_and(|l| l.contains("a1"))));
    }

    #[test]
    fn a_blocked_out_of_mandate_proposal_is_not_a_violation() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let r = mandate_run(&m, &issuer, &[("a1", "https://evil.test/p", None, false)]);
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(compliance(&report), Status::Pass);
    }

    #[test]
    fn going_over_max_actions_fails() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let r = mandate_run(
            &m,
            &issuer,
            &[
                ("a1", "https://vendor.example/p", None, true),
                ("a2", "https://vendor.example/q", None, true),
            ],
        );
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(compliance(&report), Status::Fail);
        assert!(messages(&report, Dimension::MandateCompliance).contains("max_actions"));
    }

    #[test]
    fn going_over_the_spend_bound_fails() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let r = mandate_run(
            &m,
            &issuer,
            &[("a1", "https://vendor.example/p", Some(101), true)],
        );
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(compliance(&report), Status::Fail);
    }

    #[test]
    fn a_swapped_mandate_document_fails() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let mut r = mandate_run(
            &m,
            &issuer,
            &[("a1", "https://vendor.example/p", None, true)],
        );
        // Loosen the mandate after the fact; the signature no longer fits.
        let mut loose = m.clone();
        loose.allowed_hosts.push("evil.test".to_owned());
        let old_sig = r.mandate.as_ref().unwrap().signature.clone();
        r.mandate = Some(MandateRecord {
            document_bytes: abb_jcs::to_canonical(&loose.to_value())
                .unwrap()
                .into_bytes(),
            signature: old_sig,
        });
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(compliance(&report), Status::Fail);
    }

    #[test]
    fn a_mandate_signed_by_a_non_issuer_key_fails() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let r = mandate_run(
            &m,
            &issuer,
            &[("a1", "https://vendor.example/p", None, true)],
        );
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "approver")])));
        assert_eq!(compliance(&report), Status::Fail);
    }

    #[test]
    fn a_declared_mandate_with_no_document_is_unknown() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let mut r = mandate_run(
            &m,
            &issuer,
            &[("a1", "https://vendor.example/p", None, true)],
        );
        r.mandate = None;
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(compliance(&report), Status::Unknown);
    }

    #[test]
    fn a_mandate_for_a_different_adapter_fails() {
        let issuer = key("issuer");
        let m = mandate_for(&issuer);
        let mut r = mandate_run(
            &m,
            &issuer,
            &[("a1", "https://vendor.example/p", None, true)],
        );
        r.adapter_name = "other-adapter".to_owned();
        let report = mandate_check(&r, Some(&manifest(&[(&issuer, "mandate_issuer")])));
        assert_eq!(compliance(&report), Status::Fail);
    }

    // --------------------------------------------------------- disclosures

    fn committed_event(salt: &[u8], value: &Value) -> ReceiptEvent {
        let c = field_commitment(salt, value).unwrap();
        event(
            1,
            "BROWSER_OBSERVATION",
            1000,
            r#"{"action_id":"a1"}"#,
            Some(&format!(r#"{{"card":"{c}"}}"#)),
        )
    }

    fn disclosure(salt: &[u8], value: Value) -> DisclosureRecord {
        DisclosureRecord {
            event_id: "e1".to_owned(),
            field: "card".to_owned(),
            salt_hex: hex_lower(salt),
            value,
        }
    }

    fn disclose_check(r: &Receipt) -> Report {
        let mut report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        report.set(Dimension::EvidenceIntegrity, Status::Pass);
        check_disclosures(r, &mut report);
        report
    }

    fn integrity(report: &Report) -> Status {
        report.status(Dimension::EvidenceIntegrity)
    }

    #[test]
    fn a_correct_disclosure_verifies() {
        let value = Value::Str("4111111111111111".to_owned());
        let salt = [7u8; SALT_LEN];
        let r = Receipt {
            events: vec![committed_event(&salt, &value)],
            disclosures: vec![disclosure(&salt, value)],
            ..Receipt::default()
        };
        assert_eq!(integrity(&disclose_check(&r)), Status::Pass);
    }

    #[test]
    fn a_wrong_value_or_wrong_salt_is_tampering() {
        let value = Value::Str("4111111111111111".to_owned());
        let salt = [7u8; SALT_LEN];
        let wrong_value = Receipt {
            events: vec![committed_event(&salt, &value)],
            disclosures: vec![disclosure(&salt, Value::Str("0000".to_owned()))],
            ..Receipt::default()
        };
        assert_eq!(integrity(&disclose_check(&wrong_value)), Status::Fail);
        let wrong_salt = Receipt {
            events: vec![committed_event(&salt, &value)],
            disclosures: vec![disclosure(&[8u8; SALT_LEN], value)],
            ..Receipt::default()
        };
        assert_eq!(integrity(&disclose_check(&wrong_salt)), Status::Fail);
    }

    #[test]
    fn a_short_salt_is_refused() {
        let value = Value::Str("x".to_owned());
        let r = Receipt {
            events: vec![committed_event(&[1u8; 8], &value)],
            disclosures: vec![disclosure(&[1u8; 8], value)],
            ..Receipt::default()
        };
        assert_eq!(integrity(&disclose_check(&r)), Status::Fail);
    }

    #[test]
    fn a_reused_salt_is_rejected() {
        let value = Value::Str("x".to_owned());
        let salt = [9u8; SALT_LEN];
        let mut second = committed_event(&salt, &value);
        // A second event, same salt, same field name.
        let text = String::from_utf8(second.canonical.clone())
            .unwrap()
            .replace("\"e1\"", "\"e2\"");
        second.canonical = text.into_bytes();
        let mut d2 = disclosure(&salt, value.clone());
        d2.event_id = "e2".to_owned();
        let r = Receipt {
            events: vec![committed_event(&salt, &value), second],
            disclosures: vec![disclosure(&salt, value), d2],
            ..Receipt::default()
        };
        let report = disclose_check(&r);
        assert_eq!(integrity(&report), Status::Fail);
        assert!(messages(&report, Dimension::EvidenceIntegrity).contains("reused"));
    }

    #[test]
    fn a_shredded_field_stays_valid_and_is_reported_as_unknown_content() {
        let value = Value::Str("4111111111111111".to_owned());
        let r = Receipt {
            events: vec![committed_event(&[7u8; SALT_LEN], &value)],
            ..Receipt::default()
        };
        let report = disclose_check(&r);
        // Hashes and signatures are untouched, so integrity is not failed...
        assert_eq!(integrity(&report), Status::Pass);
        // ...but the report says the content is unknown.
        assert!(messages(&report, Dimension::EvidenceIntegrity).contains("not disclosed"));
    }

    #[test]
    fn a_disclosure_for_a_field_never_committed_fails() {
        let value = Value::Str("x".to_owned());
        let mut d = disclosure(&[1u8; SALT_LEN], value.clone());
        d.field = "password".to_owned();
        let r = Receipt {
            events: vec![committed_event(&[1u8; SALT_LEN], &value)],
            disclosures: vec![d],
            ..Receipt::default()
        };
        assert_eq!(integrity(&disclose_check(&r)), Status::Fail);
    }

    #[test]
    fn the_tag_used_by_commitments_is_the_field_tag() {
        assert_eq!(tags::FIELD, "ABB1-FIELD");
    }
}
