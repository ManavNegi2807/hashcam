//! The signer's obligations, from `PROTOCOL.md` section 11 and `R-SIG-01..13`.
//!
//! The one that matters most is `arbitrary_root_attempt_is_refused`: the signer
//! recomputes the root from the canonical event bytes and never signs a root a
//! caller handed it (D-12). Everything else here is the validation order of
//! 11.2 and the fail-closed rule of 11.3.
//!
//! Every test uses its own temporary state directory and a test-only key, so
//! they are independent and leave nothing behind.

use std::path::{Path, PathBuf};

use abb_checkpoint::{tagged_bytes, tags, CheckpointPayload, ZERO_HASH_HEX};
use abb_jcs::{hex_lower, Value};
use abb_signer::{Append, Config, SignRequest, Signer, SignerError, StoredCheckpoint, StreamState};

// --------------------------------------------------------------------------- //
// fixtures
// --------------------------------------------------------------------------- //

const RUN: &str = "11111111-1111-4111-8111-111111111111";

fn seeded_key(label: &str) -> ed25519_dalek::SigningKey {
    use sha2::Digest as _;
    ed25519_dalek::SigningKey::from_bytes(&sha2::Sha256::digest(label.as_bytes()).into())
}

struct Harness {
    /// `None` while stopped. The state lock is exclusive on purpose, so a
    /// restart has to drop the running signer before opening the next one.
    signer: Option<Signer>,
    ingestion: ed25519_dalek::SigningKey,
    dir: PathBuf,
}

impl Harness {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("abb-signer-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");

        let signing = seeded_key("abb/1 test key v1 signer");
        let key_path = dir.join("signer.key");
        std::fs::write(&key_path, signing.to_bytes()).expect("write key");

        let ingestion = seeded_key("abb/1 test ingestion key");
        let signer = Signer::open(Config {
            state_dir: dir.join("state"),
            key_path,
            ingestion_public_key: ingestion.verifying_key().to_bytes(),
            rate_limit_per_second: 1_000,
        })
        .expect("signer opens");
        Self {
            signer: Some(signer),
            ingestion,
            dir,
        }
    }

    fn signer(&mut self) -> &mut Signer {
        self.signer.as_mut().expect("the signer is running")
    }

    fn key_id(&self) -> String {
        self.signer.as_ref().expect("running").key_id().to_owned()
    }

    fn stream(&self, stream_id: &str) -> Option<StreamState> {
        self.signer
            .as_ref()
            .and_then(|s| s.state(stream_id))
            .cloned()
    }

    /// Stop the signer, releasing its state lock.
    fn stop(&mut self) {
        self.signer = None;
    }

    /// Stop and start again from the same state directory, as a restart does.
    fn restart(&mut self) -> Result<(), SignerError> {
        self.stop();
        let signer = Signer::open(Config {
            state_dir: self.dir.join("state"),
            key_path: self.dir.join("signer.key"),
            ingestion_public_key: self.ingestion.verifying_key().to_bytes(),
            rate_limit_per_second: 1_000,
        })?;
        self.signer = Some(signer);
        Ok(())
    }

    fn state_log(&self) -> PathBuf {
        self.dir.join("state").join("state.log")
    }

    fn audit_log(&self) -> PathBuf {
        self.dir.join("state").join("audit.log")
    }

    /// Sign a request the way the ingestion service would: attested JSON.
    fn send(&mut self, request: &SignRequest) -> Result<StoredCheckpoint, SignerError> {
        let body = attested_body(request, &self.ingestion);
        self.signer().sign_json(&body)
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Build the request JSON and attach a valid `caller_attestation` (D-20).
fn attested_body(request: &SignRequest, ingestion: &ed25519_dalek::SigningKey) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
    let value = request.to_value();
    let signing_bytes = abb_signer::request_signing_bytes(&value).expect("signing bytes");
    let signature = hex_lower(&ingestion.sign(&signing_bytes).to_bytes());
    let Value::Object(mut entries) = value else {
        unreachable!()
    };
    entries.push(("caller_attestation".to_owned(), Value::Str(signature)));
    abb_jcs::to_canonical_with(&Value::Object(entries), &abb_jcs::Limits::relaxed())
        .expect("canonical request")
        .into_bytes()
}

/// A canonical event for `run`, at `sequence`, of `event_type`.
fn event(run: &str, sequence: i64, event_type: &str) -> Vec<u8> {
    let value = Value::Object(vec![
        ("protocol_version".into(), Value::Str("abb/1".into())),
        ("schema_version".into(), Value::Int(1)),
        ("run_id".into(), Value::Str(run.to_owned())),
        (
            "event_id".into(),
            Value::Str(format!("00000000-0000-4000-8000-{:012x}", sequence + 1)),
        ),
        ("sequence".into(), Value::Int(sequence)),
        ("event_type".into(), Value::Str(event_type.to_owned())),
        (
            "created_at".into(),
            Value::Int(1_760_000_000_000 + sequence),
        ),
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
            Value::Object(vec![("n".into(), Value::Int(sequence))]),
        ),
    ]);
    abb_jcs::canonical_bytes(&value).expect("canonical event")
}

/// The usual first batch: RUN_STARTED plus two more events.
fn first_batch(run: &str) -> Vec<Vec<u8>> {
    vec![
        event(run, 0, "RUN_STARTED"),
        event(run, 1, "ACTION_REQUESTED"),
        event(run, 2, "ACTION_AUTHORIZED"),
    ]
}

fn request(stream: &str, from: i64, events: Vec<Vec<u8>>) -> SignRequest {
    SignRequest {
        stream_id: stream.to_owned(),
        prev_checkpoint: None,
        append: Append {
            from_sequence: from,
            events,
            manifest_entries: Vec::new(),
        },
        expected_root: None,
        caller_attestation: String::new(),
    }
}

fn expected_root(events: &[Vec<u8>]) -> String {
    let leaves: Vec<Vec<u8>> = events
        .iter()
        .map(|e| tagged_bytes(tags::EVENT, e))
        .collect();
    hex_lower(&abb_merkle::mth(&leaves))
}

// --------------------------------------------------------------------------- //
// the core promise (D-12)
// --------------------------------------------------------------------------- //

#[test]
fn it_computes_the_root_itself_and_signs_a_genesis_checkpoint() {
    let mut h = Harness::new("genesis");
    let events = first_batch(RUN);
    let checkpoint = h.send(&request(RUN, 0, events.clone())).expect("signed");

    assert_eq!(checkpoint.payload.stream_id, RUN);
    assert_eq!(checkpoint.payload.tree_size, 3);
    assert_eq!(checkpoint.payload.root_hash, expected_root(&events));
    assert_eq!(checkpoint.payload.prev_checkpoint_hash, ZERO_HASH_HEX);
    assert_eq!(checkpoint.payload.manifest_size, 0);
    assert_eq!(checkpoint.payload.manifest_head, ZERO_HASH_HEX);
    assert_eq!(checkpoint.payload.key_id, h.key_id());

    // The signature verifies under the signer's own key.
    let verifying = seeded_key("abb/1 test key v1 signer").verifying_key();
    checkpoint
        .payload
        .verify(&checkpoint.signature, &verifying)
        .expect("signature verifies");
}

#[test]
fn an_arbitrary_root_attempt_is_refused() {
    // The caller claims a root that is not the root of the events it sent.
    let mut h = Harness::new("arbitrary-root");
    let mut req = request(RUN, 0, first_batch(RUN));
    req.expected_root = Some("ab".repeat(32));
    assert_eq!(h.send(&req).unwrap_err(), SignerError::RootMismatch);
    // Nothing was signed, so the stream still has no state.
    assert!(h.stream(RUN).is_none());
}

#[test]
fn a_matching_expected_root_is_accepted_as_a_cross_check() {
    let mut h = Harness::new("expected-root-ok");
    let events = first_batch(RUN);
    let mut req = request(RUN, 0, events.clone());
    req.expected_root = Some(expected_root(&events));
    let checkpoint = h.send(&req).expect("signed");
    assert_eq!(checkpoint.payload.root_hash, expected_root(&events));
}

#[test]
fn leaf_hashes_without_events_are_refused() {
    // A caller that sends digests instead of canonical bytes has nothing the
    // signer can verify, so there is no path to a signature.
    let mut h = Harness::new("leaf-hashes-only");
    let leaf = hex_lower(&abb_merkle::leaf_hash(b"whatever"));
    let body = {
        let value = Value::Object(vec![
            ("stream_id".to_owned(), Value::Str(RUN.to_owned())),
            (
                "append".to_owned(),
                Value::Object(vec![
                    ("from_sequence".to_owned(), Value::Int(0)),
                    (
                        "leaf_hashes".to_owned(),
                        Value::Array(vec![Value::Str(leaf)]),
                    ),
                ]),
            ),
        ]);
        let signing = abb_signer::request_signing_bytes(&value).expect("signing bytes");
        use ed25519_dalek::Signer as _;
        let attestation = hex_lower(&h.ingestion.sign(&signing).to_bytes());
        let Value::Object(mut entries) = value else {
            unreachable!()
        };
        entries.push(("caller_attestation".to_owned(), Value::Str(attestation)));
        abb_jcs::to_canonical_with(&Value::Object(entries), &abb_jcs::Limits::relaxed())
            .expect("canonical")
            .into_bytes()
    };
    let err = h.signer().sign_json(&body).unwrap_err();
    assert!(
        matches!(err, SignerError::BadAppendEvidence(_)),
        "expected BAD_APPEND_EVIDENCE, got {err:?}"
    );
}

// --------------------------------------------------------------------------- //
// authentication
// --------------------------------------------------------------------------- //

#[test]
fn an_unattested_or_wrongly_signed_request_is_refused() {
    let mut h = Harness::new("unauthorized");
    let req = request(RUN, 0, first_batch(RUN));

    // No attestation at all.
    let plain = abb_jcs::to_canonical_with(&req.to_value(), &abb_jcs::Limits::relaxed())
        .expect("canonical")
        .into_bytes();
    assert_eq!(
        h.signer().sign_json(&plain).unwrap_err(),
        SignerError::Unauthorized
    );

    // Signed by a key the signer does not trust.
    let stranger = seeded_key("not the ingestion service");
    let body = attested_body(&req, &stranger);
    assert_eq!(
        h.signer().sign_json(&body).unwrap_err(),
        SignerError::Unauthorized
    );

    // A valid attestation over a *different* request body is refused too.
    let other = request(RUN, 0, vec![event(RUN, 0, "RUN_STARTED")]);
    let valid_for_other = attested_body(&other, &h.ingestion);
    let swapped = {
        // keep the attestation, change the payload
        let parsed = abb_jcs::parse_bytes(&valid_for_other, &abb_jcs::Limits::relaxed()).unwrap();
        let attestation = parsed
            .get("caller_attestation")
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned();
        let Value::Object(mut entries) = req.to_value() else {
            unreachable!()
        };
        entries.push(("caller_attestation".to_owned(), Value::Str(attestation)));
        abb_jcs::to_canonical_with(&Value::Object(entries), &abb_jcs::Limits::relaxed())
            .unwrap()
            .into_bytes()
    };
    assert_eq!(
        h.signer().sign_json(&swapped).unwrap_err(),
        SignerError::Unauthorized
    );

    assert!(h.stream(RUN).is_none());
}

// --------------------------------------------------------------------------- //
// event validation (11.2 item 4)
// --------------------------------------------------------------------------- //

#[test]
fn a_run_stream_must_begin_with_run_started() {
    let mut h = Harness::new("first-event");
    let events = vec![event(RUN, 0, "ACTION_REQUESTED")];
    let err = h.send(&request(RUN, 0, events)).unwrap_err();
    assert!(matches!(err, SignerError::BadEvent(_)), "{err:?}");
}

#[test]
fn nothing_may_follow_run_finished() {
    let mut h = Harness::new("after-finish");
    let events = vec![
        event(RUN, 0, "RUN_STARTED"),
        event(RUN, 1, "RUN_FINISHED"),
        event(RUN, 2, "ACTION_REQUESTED"),
    ];
    let err = h.send(&request(RUN, 0, events)).unwrap_err();
    assert!(matches!(err, SignerError::BadEvent(_)), "{err:?}");

    // And not in a later batch either.
    let mut h = Harness::new("after-finish-2");
    let first = vec![event(RUN, 0, "RUN_STARTED"), event(RUN, 1, "RUN_FINISHED")];
    let signed = h.send(&request(RUN, 0, first)).expect("signed");
    let mut next = request(RUN, 2, vec![event(RUN, 2, "ACTION_REQUESTED")]);
    next.prev_checkpoint = Some(signed);
    let err = h.send(&next).unwrap_err();
    assert!(matches!(err, SignerError::BadEvent(_)), "{err:?}");
}

#[test]
fn a_sequence_gap_overlap_or_reordering_is_refused() {
    // Gap inside the batch.
    let mut h = Harness::new("gap");
    let events = vec![
        event(RUN, 0, "RUN_STARTED"),
        event(RUN, 2, "ACTION_REQUESTED"),
    ];
    assert_eq!(
        h.send(&request(RUN, 0, events)).unwrap_err(),
        SignerError::GapOrOverlap
    );

    // Reordered batch.
    let mut h = Harness::new("reordered");
    let events = vec![
        event(RUN, 1, "ACTION_REQUESTED"),
        event(RUN, 0, "RUN_STARTED"),
    ];
    assert_eq!(
        h.send(&request(RUN, 0, events)).unwrap_err(),
        SignerError::GapOrOverlap
    );

    // from_sequence that does not match the signer's tree size.
    let mut h = Harness::new("from-sequence");
    let events = vec![event(RUN, 5, "RUN_STARTED")];
    assert_eq!(
        h.send(&request(RUN, 5, events)).unwrap_err(),
        SignerError::GapOrOverlap
    );
}

#[test]
fn an_event_for_another_run_is_refused() {
    let mut h = Harness::new("wrong-run");
    let other = "22222222-2222-4222-8222-222222222222";
    let events = vec![
        event(RUN, 0, "RUN_STARTED"),
        event(other, 1, "ACTION_REQUESTED"),
    ];
    let err = h.send(&request(RUN, 0, events)).unwrap_err();
    assert!(matches!(err, SignerError::BadEvent(_)), "{err:?}");
}

#[test]
fn an_unknown_event_type_or_non_canonical_bytes_are_refused() {
    let mut h = Harness::new("bad-type");
    let events = vec![
        event(RUN, 0, "RUN_STARTED"),
        event(RUN, 1, "CHECKPOINT_CREATED"),
    ];
    let err = h.send(&request(RUN, 0, events)).unwrap_err();
    assert!(matches!(err, SignerError::BadEvent(_)), "{err:?}");

    // Re-canonicalizing must give identical bytes: whitespace is not allowed.
    let mut h = Harness::new("non-canonical");
    let mut events = first_batch(RUN);
    let spaced = String::from_utf8(events[1].clone())
        .unwrap()
        .replace("\":", "\" :");
    events[1] = spaced.into_bytes();
    let err = h.send(&request(RUN, 0, events)).unwrap_err();
    assert!(matches!(err, SignerError::BadEvent(_)), "{err:?}");
}

// --------------------------------------------------------------------------- //
// extension, idempotency, forks (11.2 items 2, 6, 8)
// --------------------------------------------------------------------------- //

#[test]
fn a_second_batch_extends_the_first() {
    let mut h = Harness::new("extend");
    let first = first_batch(RUN);
    let genesis = h.send(&request(RUN, 0, first.clone())).expect("genesis");

    let more = vec![
        event(RUN, 3, "ACTION_DISPATCHED"),
        event(RUN, 4, "ACTION_SUCCEEDED"),
    ];
    let mut req = request(RUN, 3, more.clone());
    req.prev_checkpoint = Some(genesis.clone());
    let second = h.send(&req).expect("extension");

    assert_eq!(second.payload.tree_size, 5);
    assert_eq!(
        second.payload.prev_checkpoint_hash,
        genesis.payload.checkpoint_hash_hex().unwrap()
    );
    let all: Vec<Vec<u8>> = first.into_iter().chain(more).collect();
    assert_eq!(second.payload.root_hash, expected_root(&all));
}

#[test]
fn a_wrong_previous_checkpoint_is_not_extending() {
    let mut h = Harness::new("not-extending");
    let genesis = h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");

    // Claim a previous checkpoint the signer never produced.
    let mut forged = genesis.clone();
    forged.payload.created_at += 1;
    let mut req = request(RUN, 3, vec![event(RUN, 3, "ACTION_DISPATCHED")]);
    req.prev_checkpoint = Some(forged);
    assert_eq!(h.send(&req).unwrap_err(), SignerError::NotExtending);
}

#[test]
fn an_empty_batch_returns_the_identical_checkpoint() {
    let mut h = Harness::new("idempotent");
    let genesis = h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");

    let mut req = request(RUN, 3, Vec::new());
    req.prev_checkpoint = Some(genesis.clone());
    let again = h.send(&req).expect("idempotent replay");

    assert_eq!(again.payload, genesis.payload);
    assert_eq!(again.signature, genesis.signature);
    assert_eq!(
        again.payload.checkpoint_hash_hex().unwrap(),
        genesis.payload.checkpoint_hash_hex().unwrap()
    );
    // The state log did not grow: nothing new was signed.
    let lines = std::fs::read_to_string(h.state_log())
        .unwrap()
        .lines()
        .count();
    assert_eq!(
        lines, 1,
        "an idempotent replay must not append to the state log"
    );
}

#[test]
fn a_second_history_from_the_same_prefix_is_refused() {
    // A caller that kept the old checkpoint and tries to build a different
    // event 3 on top of it is refused by 11.2 item 2: the previous checkpoint
    // it presents is no longer the one the signer holds. So the code that fires
    // is NOT_EXTENDING, not FORK_DETECTED.
    //
    // FORK_DETECTED is the deeper backstop, for a checkpoint that would
    // conflict with one already in the state log at the same tree size. The
    // extension checks should make it unreachable, and it is unit-tested in
    // `state.rs` rather than reachable from here.
    let mut h = Harness::new("fork");
    let genesis = h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");

    let mut req_a = request(RUN, 3, vec![event(RUN, 3, "ACTION_DISPATCHED")]);
    req_a.prev_checkpoint = Some(genesis.clone());
    let branch_a = h.send(&req_a).expect("branch a");

    let mut req_b = request(RUN, 3, vec![event(RUN, 3, "ACTION_FAILED")]);
    req_b.prev_checkpoint = Some(genesis);
    assert_eq!(h.send(&req_b).unwrap_err(), SignerError::NotExtending);

    // The signed history is still branch a, at size 4.
    let state = h.stream(RUN).expect("state");
    assert_eq!(state.tree_size, 4);
    assert_eq!(
        state.checkpoint_hash,
        branch_a.payload.checkpoint_hash_hex().unwrap()
    );
}

#[test]
fn two_signer_processes_cannot_share_one_state_directory() {
    // Two signers on one state directory could each believe it holds the
    // latest checkpoint and sign conflicting histories. The state lock is what
    // stops that, so it is part of the fork defence (R-SIG-10).
    let mut h = Harness::new("two-processes");
    h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");

    let second = Signer::open(Config {
        state_dir: h.dir.join("state"),
        key_path: h.dir.join("signer.key"),
        ingestion_public_key: h.ingestion.verifying_key().to_bytes(),
        rate_limit_per_second: 1_000,
    });
    assert!(matches!(second, Err(SignerError::StateLocked)));
}

#[test]
fn a_shrinking_stream_is_refused() {
    let mut h = Harness::new("regression");
    let genesis = h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");
    // Pretend the stream is back at size 1 and ask to append from there.
    let mut req = request(RUN, 1, vec![event(RUN, 1, "ACTION_REQUESTED")]);
    req.prev_checkpoint = Some(genesis);
    let err = h.send(&req).unwrap_err();
    assert!(
        matches!(err, SignerError::SizeRegression | SignerError::GapOrOverlap),
        "{err:?}"
    );
}

#[test]
fn an_unknown_stream_without_a_genesis_is_refused() {
    let mut h = Harness::new("unknown-stream");
    // prev_checkpoint supplied for a stream the signer has never seen.
    let fabricated = StoredCheckpoint {
        payload: CheckpointPayload {
            protocol_version: "abb/1".to_owned(),
            stream_id: RUN.to_owned(),
            tree_size: 9,
            root_hash: "ab".repeat(32),
            manifest_size: 0,
            manifest_head: ZERO_HASH_HEX.to_owned(),
            prev_checkpoint_hash: ZERO_HASH_HEX.to_owned(),
            key_id: h.key_id(),
            created_at: 1_760_000_000_000,
        },
        signature: "00".repeat(64),
    };
    let mut req = request(RUN, 9, vec![event(RUN, 9, "ACTION_REQUESTED")]);
    req.prev_checkpoint = Some(fabricated);
    let err = h.send(&req).unwrap_err();
    assert!(
        matches!(err, SignerError::UnknownStream | SignerError::BadGenesis),
        "{err:?}"
    );
}

// --------------------------------------------------------------------------- //
// state log, durability and fail-closed (11.3)
// --------------------------------------------------------------------------- //

#[test]
fn state_survives_a_restart_and_the_log_is_hash_chained() {
    let mut h = Harness::new("restart");
    let genesis = h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");

    h.restart().expect("restarts");
    let state = h.stream(RUN).expect("state for the stream");
    assert_eq!(state.tree_size, 3);
    assert_eq!(state.root_hash, genesis.payload.root_hash);
    assert_eq!(
        state.checkpoint_hash,
        genesis.payload.checkpoint_hash_hex().unwrap()
    );

    // Every entry carries the hash of the one before it.
    let text = std::fs::read_to_string(h.state_log()).unwrap();
    let first_line = text.lines().next().unwrap();
    assert!(
        first_line.contains("\"prev_entry_hash\":\""),
        "{first_line}"
    );
}

#[test]
fn a_corrupt_state_log_makes_the_signer_fail_closed() {
    let mut h = Harness::new("corrupt");
    h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");
    h.stop();

    // Tamper with the recorded tree size, as a host administrator could.
    let text = std::fs::read_to_string(h.state_log()).unwrap();
    let broken = text.replacen("\"tree_size\":3", "\"tree_size\":4", 1);
    assert_ne!(text, broken, "the test must actually change the log");
    std::fs::write(h.state_log(), broken).unwrap();

    match h.restart() {
        Err(SignerError::StateCorrupt) => {}
        Err(other) => panic!("expected STATE_CORRUPT, got {other:?}"),
        Ok(()) => panic!("the signer opened a corrupt state log instead of failing closed"),
    }
}

#[test]
fn a_truncated_state_log_entry_also_fails_closed() {
    let mut h = Harness::new("truncated");
    h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");
    h.stop();
    let text = std::fs::read_to_string(h.state_log()).unwrap();
    std::fs::write(h.state_log(), &text[..text.len() / 2]).unwrap();
    assert_eq!(h.restart().unwrap_err(), SignerError::StateCorrupt);
}

#[test]
fn the_signer_writes_an_audit_line_per_request_without_secrets() {
    let mut h = Harness::new("audit");
    let genesis = h.send(&request(RUN, 0, first_batch(RUN))).expect("genesis");
    // A well-formed extension that claims the wrong root.
    let mut bad = request(RUN, 3, vec![event(RUN, 3, "ACTION_DISPATCHED")]);
    bad.prev_checkpoint = Some(genesis);
    bad.expected_root = Some("ab".repeat(32));
    assert_eq!(h.send(&bad).unwrap_err(), SignerError::RootMismatch);

    let audit = std::fs::read_to_string(h.audit_log()).expect("audit log");
    let lines: Vec<&str> = audit.lines().collect();
    assert_eq!(lines.len(), 2, "one line per request:\n{audit}");
    assert!(lines[0].contains("\"result\":\"SIGNED\""), "{}", lines[0]);
    assert!(
        lines[1].contains(r#""result":"ROOT_MISMATCH""#),
        "{}",
        lines[1]
    );

    // The key must not appear anywhere in the audit log.
    let key_hex = hex_lower(&seeded_key("abb/1 test key v1 signer").to_bytes());
    assert!(
        !audit.contains(&key_hex),
        "the signing key leaked into the audit log"
    );
}

#[test]
fn the_rate_limit_refuses_a_flood() {
    let dir = std::env::temp_dir().join(format!("abb-signer-rate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signing = seeded_key("abb/1 test key v1 signer");
    std::fs::write(dir.join("signer.key"), signing.to_bytes()).unwrap();
    let ingestion = seeded_key("abb/1 test ingestion key");
    let mut signer = Signer::open(Config {
        state_dir: dir.join("state"),
        key_path: dir.join("signer.key"),
        ingestion_public_key: ingestion.verifying_key().to_bytes(),
        rate_limit_per_second: 1,
    })
    .unwrap();

    let body = attested_body(&request(RUN, 0, first_batch(RUN)), &ingestion);
    signer
        .sign_json(&body)
        .expect("the first request is within the limit");
    // The second, immediately after, is not.
    let second = attested_body(&request(RUN, 0, first_batch(RUN)), &ingestion);
    assert_eq!(
        signer.sign_json(&second).unwrap_err(),
        SignerError::RateLimited
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// --------------------------------------------------------------------------- //
// the global stream (D-10, R-GLB-02)
// --------------------------------------------------------------------------- //

fn run_root_record(run_id: &str, checkpoint: &StoredCheckpoint) -> Vec<u8> {
    let value = Value::Object(vec![
        ("run_id".into(), Value::Str(run_id.to_owned())),
        (
            "checkpoint_hash".into(),
            Value::Str(checkpoint.payload.checkpoint_hash_hex().unwrap()),
        ),
        ("tree_size".into(), Value::Int(checkpoint.payload.tree_size)),
        (
            "root_hash".into(),
            Value::Str(checkpoint.payload.root_hash.clone()),
        ),
        (
            "manifest_head".into(),
            Value::Str(checkpoint.payload.manifest_head.clone()),
        ),
        (
            "finalized_at".into(),
            Value::Int(checkpoint.payload.created_at),
        ),
    ]);
    abb_jcs::canonical_bytes(&value).expect("canonical record")
}

#[test]
fn the_global_stream_accepts_a_root_the_signer_signed_itself() {
    let mut h = Harness::new("global-ok");
    let run_checkpoint = h
        .send(&request(RUN, 0, first_batch(RUN)))
        .expect("run checkpoint");
    let record = run_root_record(RUN, &run_checkpoint);

    let global = h
        .send(&request("global", 0, vec![record.clone()]))
        .expect("global checkpoint");
    assert_eq!(global.payload.stream_id, "global");
    assert_eq!(global.payload.tree_size, 1);
    assert_eq!(global.payload.manifest_size, 0);
    assert_eq!(global.payload.manifest_head, ZERO_HASH_HEX);
    let leaf = tagged_bytes(tags::RUNROOT, &record);
    assert_eq!(
        global.payload.root_hash,
        hex_lower(&abb_merkle::mth(&[leaf]))
    );
}

#[test]
fn the_global_stream_refuses_a_root_the_signer_never_signed() {
    // R-GLB-02: a run root can only enter the global log if its checkpoint is
    // in the signer's own state log. Otherwise anyone could inject a run.
    let mut h = Harness::new("global-injected");
    let real = h
        .send(&request(RUN, 0, first_batch(RUN)))
        .expect("run checkpoint");
    let mut forged = real.clone();
    forged.payload.tree_size = 99; // a checkpoint the signer never produced
    let record = run_root_record(RUN, &forged);

    let err = h.send(&request("global", 0, vec![record])).unwrap_err();
    assert!(
        matches!(err, SignerError::BadAppendEvidence(ref why) if why.contains("NOT_IN_SIGNER_STATE_LOG")),
        "{err:?}"
    );
}

// --------------------------------------------------------------------------- //
// what the signer does not hold
// --------------------------------------------------------------------------- //

#[test]
fn the_signer_has_no_database_credentials_in_its_configuration() {
    // R-SIG-02: the configuration surface is a key path, a state directory, an
    // ingestion public key and a rate limit. There is nowhere to put a DSN.
    let config = Config {
        state_dir: Path::new("state").to_path_buf(),
        key_path: Path::new("signer.key").to_path_buf(),
        ingestion_public_key: [0u8; 32],
        rate_limit_per_second: 10,
    };
    let rendered = format!("{config:?}");
    for forbidden in ["postgres", "dsn", "password", "database"] {
        assert!(!rendered.to_lowercase().contains(forbidden), "{rendered}");
    }
}

#[test]
fn error_codes_match_the_protocol_table() {
    // PROTOCOL.md 11.4 and ERROR_HANDLING.md 4.2.
    let expected = [
        (SignerError::Unauthorized, "UNAUTHORIZED"),
        (SignerError::UnknownStream, "UNKNOWN_STREAM"),
        (SignerError::BadGenesis, "BAD_GENESIS"),
        (SignerError::NotExtending, "NOT_EXTENDING"),
        (SignerError::SizeRegression, "SIZE_REGRESSION"),
        (SignerError::ForkDetected, "FORK_DETECTED"),
        (SignerError::RootMismatch, "ROOT_MISMATCH"),
        (SignerError::GapOrOverlap, "GAP_OR_OVERLAP"),
        (SignerError::RateLimited, "RATE_LIMITED"),
        (SignerError::StateCorrupt, "STATE_CORRUPT"),
    ];
    for (error, code) in expected {
        assert_eq!(error.as_str(), code);
    }
    assert_eq!(SignerError::BadEvent("x".into()).as_str(), "BAD_EVENT");
    assert_eq!(
        SignerError::BadAppendEvidence("x".into()).as_str(),
        "BAD_APPEND_EVIDENCE"
    );
}
