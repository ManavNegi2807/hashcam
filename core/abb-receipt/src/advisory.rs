//! The advisory channels in a receipt: semantic invariants and the prompt guard
//! (`PROTOCOL.md` 5.2 and 16, `R-SEM-*`, `R-PIG-*`, `R-UI-05`).
//!
//! These records are **advisory**. They never grant a permission and, by the
//! requirement table, never change the overall result by themselves. The
//! verifier's job here is narrow and strict:
//!
//! * a malformed record is a `FAIL` of its own dimension, not something to skip;
//! * no record at all is `UNKNOWN`, never `PASS` (`R-SEM-04`);
//! * a finding names the invariant and the exact event range (`R-SEM-03`);
//! * a clean prompt-guard run is reported with its limits, because "no injection
//!   flagged" is not "no injection" (`R-PIG-10`), and a high score is not proof
//!   of an attack (`R-UI-05`).

use std::collections::BTreeMap;

use abb_jcs::Value;
use abb_verify::{Dimension, Report, Status};

use crate::Receipt;

const SEMANTIC_RESULTS: [&str; 3] = ["PASS", "FAIL", "UNKNOWN"];
const SEVERITIES: [&str; 4] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const VIOLATION_STATUSES: [&str; 3] = ["OPEN", "ACKNOWLEDGED", "ESCALATED"];
const GUARD_VERDICTS: [&str; 3] = ["ALLOW", "FLAG_FOR_REVIEW", "BLOCK_BY_POLICY"];

struct Ev {
    sequence: i64,
    event_id: String,
    event_type: String,
    payload: Value,
}

fn events_of(receipt: &Receipt) -> Vec<Ev> {
    receipt
        .events
        .iter()
        .filter_map(|event| {
            let text = std::str::from_utf8(&event.canonical).ok()?;
            let value = abb_jcs::parse(text).ok()?;
            Some(Ev {
                sequence: value.get("sequence").and_then(Value::as_int).unwrap_or(-1),
                event_id: value
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                event_type: value
                    .get("event_type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                payload: value.get("payload").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

fn text<'a>(payload: &'a Value, name: &str) -> Option<&'a str> {
    payload.get(name).and_then(Value::as_str)
}

fn is_hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A version can be written as a string or an integer; show either.
fn version_of(payload: &Value) -> String {
    match payload.get("invariant_version") {
        Some(Value::Str(s)) => s.clone(),
        Some(Value::Int(n)) => n.to_string(),
        _ => "?".to_owned(),
    }
}

/// The evidence ids of a record, and the sequence range they cover in this receipt.
fn evidence_range(payload: &Value, by_id: &BTreeMap<&str, i64>) -> (Vec<String>, String) {
    let ids: Vec<String> = payload
        .get("evidence_event_ids")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let sequences: Vec<i64> = ids
        .iter()
        .filter_map(|id| by_id.get(id.as_str()).copied())
        .collect();
    let range = match (sequences.iter().min(), sequences.iter().max()) {
        (Some(low), Some(high)) if low == high => format!("event sequence {low}"),
        (Some(low), Some(high)) => format!("event sequences {low} to {high}"),
        _ => "no evidence event in this receipt".to_owned(),
    };
    (ids, range)
}

/// Semantic invariants: `PASS` only when at least one was checked and none
/// failed or was unknown.
pub fn check_semantic(receipt: &Receipt, report: &mut Report) {
    let dim = Dimension::SemanticAssessment;
    let events = events_of(receipt);
    let by_id: BTreeMap<&str, i64> = events
        .iter()
        .map(|e| (e.event_id.as_str(), e.sequence))
        .collect();

    let mut checked = 0usize;
    let mut unknown = 0usize;
    let mut failed = false;

    for ev in &events {
        match ev.event_type.as_str() {
            "SEMANTIC_INVARIANT_CHECKED" => {
                let id = text(&ev.payload, "invariant_id").unwrap_or("?");
                let locator = Some(format!("invariant {id} v{}", version_of(&ev.payload)));
                let Some(result) = text(&ev.payload, "result") else {
                    report.fail(dim, locator, "a semantic record has no result");
                    failed = true;
                    continue;
                };
                if !SEMANTIC_RESULTS.contains(&result) {
                    report.fail(dim, locator, format!("unknown semantic result {result}"));
                    failed = true;
                    continue;
                }
                checked += 1;
                let (_, range) = evidence_range(&ev.payload, &by_id);
                match result {
                    "FAIL" => {
                        report.fail(dim, locator, format!("invariant failed; evidence: {range}"));
                        failed = true;
                    }
                    "UNKNOWN" => {
                        unknown += 1;
                        report.note(
                            dim,
                            locator,
                            format!(
                                "could not be decided (a step was missing or unobserved); {range}"
                            ),
                        );
                    }
                    _ => {}
                }
            }
            "SEMANTIC_VIOLATION_DETECTED" => {
                let id = text(&ev.payload, "invariant_id").unwrap_or("?");
                let locator = Some(format!("invariant {id} v{}", version_of(&ev.payload)));
                let severity = text(&ev.payload, "severity").unwrap_or_default();
                let status = text(&ev.payload, "status").unwrap_or_default();
                if !SEVERITIES.contains(&severity) || !VIOLATION_STATUSES.contains(&status) {
                    report.fail(dim, locator, "a semantic violation record is malformed");
                    failed = true;
                    continue;
                }
                let (_, range) = evidence_range(&ev.payload, &by_id);
                report.fail(
                    dim,
                    locator,
                    format!(
                        "violation, severity {severity}, status {status}; evidence: {range}. \
                         A finding is a signal, not a verdict"
                    ),
                );
                failed = true;
            }
            _ => {}
        }
    }

    if failed {
        return;
    }
    if checked == 0 {
        report.set(dim, Status::Unknown);
        report.note(dim, None, "no semantic records in the receipt");
    } else if unknown > 0 {
        report.set(dim, Status::Unknown);
    } else {
        report.set(dim, Status::Pass);
        report.note(
            dim,
            None,
            format!(
                "{checked} deterministic invariant(s) held on the observed events. This covers \
                 only what the invariants describe, and only what was observed"
            ),
        );
    }
}

/// The prompt guard. A clean run is `PASS` with its limits stated; a flag or a
/// block is an advisory `FAIL` that names the source digest.
pub fn check_prompt_security(receipt: &Receipt, report: &mut Report) {
    let dim = Dimension::PromptSecurityAssessment;
    let events = events_of(receipt);

    let mut analyses = 0usize;
    let mut failed = false;
    let mut classifier_seen_on = false;

    for ev in events
        .iter()
        .filter(|e| e.event_type == "PROMPT_SECURITY_ANALYSIS_COMPLETED")
    {
        let locator = Some(format!("event {} (sequence {})", ev.event_id, ev.sequence));
        let verdict = text(&ev.payload, "verdict").unwrap_or_default();
        let score = ev.payload.get("score_ppm").and_then(Value::as_int);
        let source = text(&ev.payload, "source_digest").unwrap_or_default();
        let detector = text(&ev.payload, "detector_id").unwrap_or_default();
        let has_classifier_flag = ev.payload.get("classifier_available").is_some();
        let well_formed = GUARD_VERDICTS.contains(&verdict)
            && score.is_some_and(|s| (0..=1_000_000).contains(&s))
            && is_hex64(source)
            && !detector.is_empty()
            && has_classifier_flag
            && ev
                .payload
                .get("reason_codes")
                .and_then(Value::as_array)
                .is_some();
        if !well_formed {
            report.fail(dim, locator, "a prompt-security record is malformed");
            failed = true;
            continue;
        }
        analyses += 1;
        if matches!(
            ev.payload.get("classifier_available"),
            Some(Value::Bool(true))
        ) {
            classifier_seen_on = true;
        }
        if verdict != "ALLOW" {
            let reasons = ev
                .payload
                .get("reason_codes")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            report.fail(
                dim,
                locator,
                format!(
                    "guard verdict {verdict} (score {} ppm; reasons: {reasons}) on input {source}. \
                     This is a signal for review, not proof of an attack",
                    score.unwrap_or_default()
                ),
            );
            failed = true;
        }
    }

    if failed {
        return;
    }
    if analyses == 0 {
        report.set(dim, Status::Unknown);
        report.note(dim, None, "no prompt-security records in the receipt");
        return;
    }
    report.set(dim, Status::Pass);
    report.note(
        dim,
        None,
        format!(
            "{analyses} input(s) screened and none flagged. {} Not flagged is not the same as \
             safe: this is not a complete prompt-injection defence",
            if classifier_seen_on {
                "A classifier was available."
            } else {
                "Deterministic checks only; the classifier was not available."
            }
        ),
    );
}

/// What an analysis record may carry (`R-ANO-10`): identifiers and numbers, nothing
/// executable. Anything else, a model body for example, is refused.
const ANALYSIS_FIELDS: [&str; 7] = [
    "model_id",
    "model_version",
    "feature_schema_id",
    "score_ppm",
    "reason_codes",
    "score_kind",
    "threshold_ppm",
];

/// The behavior-anomaly channel. Rules and replay-drift write
/// `ML_ANALYSIS_COMPLETED`. A score here is a rule score, not a probability
/// (`R-ANO-09`), and a high one is a signal, not proof of malice (`R-UI-05`).
pub fn check_anomaly(receipt: &Receipt, report: &mut Report) {
    let dim = Dimension::BehaviorAnomalyAssessment;
    let events = events_of(receipt);

    let mut analyses = 0usize;
    let mut failed = false;
    for ev in events
        .iter()
        .filter(|e| e.event_type == "ML_ANALYSIS_COMPLETED")
    {
        let locator = Some(format!("event {} (sequence {})", ev.event_id, ev.sequence));
        let Some(entries) = ev.payload.as_object() else {
            report.fail(dim, locator, "an analysis record is not an object");
            failed = true;
            continue;
        };
        if let Some((name, _)) = entries
            .iter()
            .find(|(name, _)| !ANALYSIS_FIELDS.contains(&name.as_str()))
        {
            report.fail(
                dim,
                locator,
                format!(
                    "an analysis record carries a field it may not ({name}): receipts hold \
                     identifiers and scores only, never a model"
                ),
            );
            failed = true;
            continue;
        }
        let score = ev.payload.get("score_ppm").and_then(Value::as_int);
        let well_formed = text(&ev.payload, "model_id").is_some_and(|t| !t.is_empty())
            && text(&ev.payload, "model_version").is_some()
            && text(&ev.payload, "feature_schema_id").is_some_and(|t| !t.is_empty())
            && score.is_some_and(|s| (0..=1_000_000).contains(&s))
            && ev
                .payload
                .get("reason_codes")
                .and_then(Value::as_array)
                .is_some();
        if !well_formed {
            report.fail(dim, locator, "an analysis record is malformed");
            failed = true;
            continue;
        }
        analyses += 1;
        let reasons: Vec<&str> = ev
            .payload
            .get("reason_codes")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if !reasons.is_empty() {
            report.fail(
                dim,
                locator,
                format!(
                    "{} flagged: {} (rule score {} ppm, not a probability). This is a signal \
                     for review, not proof of malice",
                    text(&ev.payload, "model_id").unwrap_or("analysis"),
                    reasons.join(", "),
                    score.unwrap_or_default()
                ),
            );
            failed = true;
        }
    }

    if failed {
        return;
    }
    if analyses == 0 {
        report.set(dim, Status::Unknown);
        report.note(dim, None, "no behavior analysis in the receipt");
        return;
    }
    report.set(dim, Status::Pass);
    report.note(
        dim,
        None,
        format!(
            "{analyses} analysis run(s) flagged nothing. These are readable rules and drift \
             comparisons, not a trained model, and a quiet result does not mean the behavior \
             was fine"
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReceiptEvent;
    use abb_verify::{Profile, ReceiptShape};

    fn event(seq: i64, kind: &str, payload: &str) -> ReceiptEvent {
        let text = format!(
            r#"{{"event_id":"e{seq}","event_type":"{kind}","created_at":1,"sequence":{seq},"payload":{payload}}}"#
        );
        let canonical = abb_jcs::to_canonical(&abb_jcs::parse(&text).unwrap()).unwrap();
        ReceiptEvent {
            canonical: canonical.into_bytes(),
            leaf_index: 0,
            tree_size: 0,
            path: Vec::new(),
        }
    }

    fn receipt(events: Vec<ReceiptEvent>) -> Receipt {
        Receipt {
            events,
            ..Receipt::default()
        }
    }

    fn semantic(r: &Receipt) -> (Status, String) {
        let mut report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        check_semantic(r, &mut report);
        (
            report.status(Dimension::SemanticAssessment),
            report
                .details
                .iter()
                .map(|d| format!("{} {}", d.locator.clone().unwrap_or_default(), d.message))
                .collect::<Vec<_>>()
                .join(" | "),
        )
    }

    fn guard(r: &Receipt) -> (Status, String) {
        let mut report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        check_prompt_security(r, &mut report);
        (
            report.status(Dimension::PromptSecurityAssessment),
            report
                .details
                .iter()
                .map(|d| d.message.clone())
                .collect::<Vec<_>>()
                .join(" | "),
        )
    }

    fn checked(seq: i64, id: &str, result: &str, evidence: &str) -> ReceiptEvent {
        event(
            seq,
            "SEMANTIC_INVARIANT_CHECKED",
            &format!(
                r#"{{"invariant_id":"{id}","invariant_version":"1","result":"{result}","evidence_event_ids":[{evidence}]}}"#
            ),
        )
    }

    fn analysis(seq: i64, verdict: &str, score: i64) -> ReceiptEvent {
        event(
            seq,
            "PROMPT_SECURITY_ANALYSIS_COMPLETED",
            &format!(
                r#"{{"detector_id":"deterministic","detector_version":"1","verdict":"{verdict}","score_ppm":{score},"reason_codes":["ROLE_CONFUSION"],"source_digest":"{}","classifier_available":false}}"#,
                "ab".repeat(32)
            ),
        )
    }

    fn anomaly(r: &Receipt) -> (Status, String) {
        let mut report = Report::new(Profile::LocalOnly, ReceiptShape::default());
        check_anomaly(r, &mut report);
        (
            report.status(Dimension::BehaviorAnomalyAssessment),
            report
                .details
                .iter()
                .map(|d| d.message.clone())
                .collect::<Vec<_>>()
                .join(" | "),
        )
    }

    fn analysis_record(extra: &str, reasons: &str, score: i64) -> ReceiptEvent {
        event(
            1,
            "ML_ANALYSIS_COMPLETED",
            &format!(
                r#"{{"model_id":"abb-anomaly-rules","model_version":"1","feature_schema_id":"abb-features-v1","score_ppm":{score},"reason_codes":[{reasons}]{extra}}}"#
            ),
        )
    }

    #[test]
    fn no_analysis_is_unknown_never_pass() {
        assert_eq!(
            anomaly(&receipt(vec![event(1, "RUN_STARTED", "{}")])).0,
            Status::Unknown
        );
    }

    #[test]
    fn a_quiet_analysis_passes_with_its_limits_stated() {
        let (status, text) = anomaly(&receipt(vec![analysis_record("", "", 0)]));
        assert_eq!(status, Status::Pass);
        assert!(text.contains("not a trained model"), "{text}");
    }

    #[test]
    fn a_flagged_analysis_fails_the_advisory_channel_and_says_it_is_not_a_probability() {
        let (status, text) = anomaly(&receipt(vec![analysis_record(
            "",
            r#""ANO-LOOP""#,
            400_000,
        )]));
        assert_eq!(status, Status::Fail);
        assert!(
            text.contains("ANO-LOOP") && text.contains("not a probability"),
            "{text}"
        );
        assert!(text.contains("not proof of malice"), "{text}");
    }

    #[test]
    fn a_model_body_in_a_record_is_refused() {
        for extra in [
            r#","model_bytes":"gASV..""#,
            r#","pickle":"x""#,
            r#","weights":[1,2,3]"#,
        ] {
            let (status, text) = anomaly(&receipt(vec![analysis_record(extra, "", 0)]));
            assert_eq!(status, Status::Fail, "{extra}");
            assert!(text.contains("never a model"), "{text}");
        }
    }

    #[test]
    fn malformed_analysis_records_fail() {
        for payload in [
            r#"{"model_id":"","model_version":"1","feature_schema_id":"f","score_ppm":1,"reason_codes":[]}"#,
            r#"{"model_id":"m","model_version":"1","feature_schema_id":"f","score_ppm":-1,"reason_codes":[]}"#,
            r#"{"model_id":"m","model_version":"1","feature_schema_id":"f","score_ppm":2000000,"reason_codes":[]}"#,
            r#"{"model_id":"m","model_version":"1","feature_schema_id":"f","score_ppm":1}"#,
        ] {
            let r = receipt(vec![event(1, "ML_ANALYSIS_COMPLETED", payload)]);
            assert_eq!(anomaly(&r).0, Status::Fail, "{payload}");
        }
    }

    #[test]
    fn no_semantic_records_is_unknown_never_pass() {
        let (status, _) = semantic(&receipt(vec![event(1, "RUN_STARTED", "{}")]));
        assert_eq!(status, Status::Unknown);
    }

    #[test]
    fn invariants_that_all_held_pass_with_their_limits_stated() {
        let r = receipt(vec![
            checked(1, "INV-A", "PASS", ""),
            checked(2, "INV-B", "PASS", ""),
        ]);
        let (status, text) = semantic(&r);
        assert_eq!(status, Status::Pass);
        assert!(text.contains("only what was observed"));
    }

    #[test]
    fn a_failed_invariant_names_itself_and_the_event_range() {
        let r = receipt(vec![
            event(1, "ACTION_REQUESTED", "{}"),
            event(2, "ACTION_DISPATCHED", "{}"),
            event(3, "ACTION_DISPATCHED", "{}"),
            checked(4, "INV-DISPATCH-AFTER-AUTH", "FAIL", r#""e2","e3""#),
        ]);
        let (status, text) = semantic(&r);
        assert_eq!(status, Status::Fail);
        assert!(text.contains("INV-DISPATCH-AFTER-AUTH"), "{text}");
        assert!(text.contains("event sequences 2 to 3"), "{text}");
    }

    #[test]
    fn an_undecidable_invariant_makes_the_channel_unknown() {
        let r = receipt(vec![
            checked(1, "INV-A", "PASS", ""),
            checked(2, "INV-B", "UNKNOWN", ""),
        ]);
        assert_eq!(semantic(&r).0, Status::Unknown);
    }

    #[test]
    fn a_violation_record_fails_and_states_it_is_a_signal() {
        let r = receipt(vec![
            event(1, "ACTION_DISPATCHED", "{}"),
            event(
                2,
                "SEMANTIC_VIOLATION_DETECTED",
                r#"{"invariant_id":"INV-X","invariant_version":"1","severity":"HIGH","evidence_event_ids":["e1"],"status":"OPEN"}"#,
            ),
        ]);
        let (status, text) = semantic(&r);
        assert_eq!(status, Status::Fail);
        assert!(text.contains("signal, not a verdict"), "{text}");
        assert!(text.contains("event sequence 1"), "{text}");
    }

    #[test]
    fn malformed_semantic_records_fail_rather_than_being_skipped() {
        for payload in [
            r#"{"invariant_id":"X","invariant_version":"1","evidence_event_ids":[]}"#,
            r#"{"invariant_id":"X","invariant_version":"1","result":"MAYBE","evidence_event_ids":[]}"#,
        ] {
            let r = receipt(vec![event(1, "SEMANTIC_INVARIANT_CHECKED", payload)]);
            assert_eq!(semantic(&r).0, Status::Fail, "{payload}");
        }
        let bad_violation = receipt(vec![event(
            1,
            "SEMANTIC_VIOLATION_DETECTED",
            r#"{"invariant_id":"X","invariant_version":"1","severity":"EXTREME","evidence_event_ids":[],"status":"OPEN"}"#,
        )]);
        assert_eq!(semantic(&bad_violation).0, Status::Fail);
    }

    #[test]
    fn evidence_missing_from_the_receipt_is_said_plainly() {
        let r = receipt(vec![checked(
            1,
            "INV-A",
            "FAIL",
            r#""not-in-this-receipt""#,
        )]);
        let (_, text) = semantic(&r);
        assert!(text.contains("no evidence event in this receipt"), "{text}");
    }

    #[test]
    fn no_guard_records_is_unknown_never_pass() {
        assert_eq!(
            guard(&receipt(vec![event(1, "RUN_STARTED", "{}")])).0,
            Status::Unknown
        );
    }

    #[test]
    fn a_clean_guard_run_passes_but_says_what_that_does_not_mean() {
        let (status, text) = guard(&receipt(vec![analysis(1, "ALLOW", 0)]));
        assert_eq!(status, Status::Pass);
        assert!(
            text.contains("not a complete prompt-injection defence"),
            "{text}"
        );
        assert!(text.contains("classifier was not available"), "{text}");
    }

    #[test]
    fn a_flag_or_block_fails_the_advisory_channel_with_the_source_and_a_caveat() {
        for verdict in ["FLAG_FOR_REVIEW", "BLOCK_BY_POLICY"] {
            let (status, text) = guard(&receipt(vec![analysis(1, verdict, 750_000)]));
            assert_eq!(status, Status::Fail, "{verdict}");
            assert!(text.contains(verdict));
            assert!(text.contains(&"ab".repeat(32)));
            assert!(text.contains("not proof of an attack"), "{text}");
        }
    }

    #[test]
    fn malformed_guard_records_fail() {
        let bad = [
            r#"{"detector_id":"d","verdict":"ALLOW","score_ppm":-1,"reason_codes":[],"source_digest":"ab","classifier_available":false}"#,
            r#"{"detector_id":"d","verdict":"MAYBE","score_ppm":1,"reason_codes":[],"source_digest":"ab","classifier_available":false}"#,
        ];
        for payload in bad {
            let r = receipt(vec![event(
                1,
                "PROMPT_SECURITY_ANALYSIS_COMPLETED",
                payload,
            )]);
            assert_eq!(guard(&r).0, Status::Fail, "{payload}");
        }
        // classifier_available is mandatory: a record that omits it hides a limit.
        let no_flag = format!(
            r#"{{"detector_id":"d","verdict":"ALLOW","score_ppm":1,"reason_codes":[],"source_digest":"{}"}}"#,
            "ab".repeat(32)
        );
        let r = receipt(vec![event(
            1,
            "PROMPT_SECURITY_ANALYSIS_COMPLETED",
            &no_flag,
        )]);
        assert_eq!(guard(&r).0, Status::Fail);
    }

    #[test]
    fn a_score_above_a_million_parts_per_million_is_refused() {
        let r = receipt(vec![analysis(1, "BLOCK_BY_POLICY", 1_000_001)]);
        assert_eq!(guard(&r).0, Status::Fail);
    }
}
