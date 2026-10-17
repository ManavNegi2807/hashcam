-- Agent Black Box: initial schema (Step 3 of docs/IMPLEMENTATION_PLAN.md).
--
-- Source of truth: DATABASE_AND_API_CONTRACTS.md Part A. Where this file and
-- PROTOCOL.md disagree, PROTOCOL.md wins.
--
-- Hackathon cut (D-13, R-HKC-02): plain PostgreSQL, no TimescaleDB. The ledger
-- stays in ordinary tables. Migrations are forward-only.
--
-- What this schema does NOT do: stop a database administrator. A superuser can
-- disable a trigger and rewrite any row. Checkpoints, the global log, witnesses
-- and anchors are the defence (R-DAT-06, SECURITY.md 16).

BEGIN;

CREATE TABLE schema_migrations (
  version     integer PRIMARY KEY,
  applied_at  timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Keys, mandates, users (referenced by runs and approvals)
-- ---------------------------------------------------------------------------

CREATE TABLE key_manifest (
  key_id                  text PRIMARY KEY,
  public_key              bytea NOT NULL CHECK (octet_length(public_key) = 32),
  role                    text  NOT NULL CHECK (role IN ('signer','witness','approver','mandate_issuer')),
  failure_domain          text,
  valid_from_ms           bigint NOT NULL,
  status                  text  NOT NULL CHECK (status IN ('active','retired','revoked')),
  last_trusted_checkpoint bytea
);

CREATE TABLE mandates (
  mandate_id     text  PRIMARY KEY,
  mandate_bytes  bytea NOT NULL,
  signature      bytea NOT NULL CHECK (octet_length(signature) = 64),
  issuer_key_id  text  NOT NULL REFERENCES key_manifest(key_id)
);

CREATE TABLE users (
  user_id   uuid PRIMARY KEY,
  name      text NOT NULL,
  role      text NOT NULL CHECK (role IN ('admin','operator','adapter','approver','auditor')),
  disabled  boolean NOT NULL DEFAULT false
);

CREATE TABLE api_tokens (
  token_id      uuid PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES users(user_id),
  token_hash    bytea NOT NULL UNIQUE,   -- SHA-256 of the token; the token itself is shown once
  scope_run_id  uuid,                    -- optional restriction to one run
  expires_at_ms bigint NOT NULL,
  revoked       boolean NOT NULL DEFAULT false
);

-- ---------------------------------------------------------------------------
-- Policy
-- ---------------------------------------------------------------------------

CREATE TABLE policy_versions (
  policy_id     text    NOT NULL,
  version       integer NOT NULL,
  body_json     jsonb   NOT NULL,
  body_digest   bytea   NOT NULL CHECK (octet_length(body_digest) = 32),
  created_at_ms bigint  NOT NULL,
  PRIMARY KEY (policy_id, version)
);

-- ---------------------------------------------------------------------------
-- Runs and state
-- ---------------------------------------------------------------------------

CREATE TABLE runs (
  run_id              uuid PRIMARY KEY,
  task_digest         bytea   NOT NULL CHECK (octet_length(task_digest) = 32),
  adapter_name        text    NOT NULL,
  adapter_version     text    NOT NULL,
  mode                text    NOT NULL CHECK (mode IN ('REPLAY','LIVE_LOCAL','LIVE_EXTERNAL')),
  profile             text    NOT NULL CHECK (profile IN ('LOCAL_ONLY','CONNECTED_EVIDENCE')),
  requested_coverage  text    NOT NULL CHECK (requested_coverage IN ('TASK_LEVEL','STEP_OBSERVED','STEP_GATED')),
  declared_coverage   text    CHECK (declared_coverage IN ('TASK_LEVEL','STEP_OBSERVED','STEP_GATED')),
  policy_id           text    NOT NULL,
  policy_version      integer NOT NULL,
  mandate_id          text    REFERENCES mandates(mandate_id),
  state               text    NOT NULL,
  created_by          text    NOT NULL,
  created_at_ms       bigint  NOT NULL,
  FOREIGN KEY (policy_id, policy_version) REFERENCES policy_versions(policy_id, version)
);

CREATE TABLE run_state_transitions (
  run_id      uuid    NOT NULL REFERENCES runs(run_id),
  seq         integer NOT NULL,
  from_state  text    NOT NULL,
  to_state    text    NOT NULL,
  reason      text,
  at_ms       bigint  NOT NULL,
  PRIMARY KEY (run_id, seq)
);

-- The legal transition table of PROTOCOL.md section 6. Anything not listed
-- here is rejected at the database boundary as well as in the service.
CREATE TABLE run_state_transitions_allowed (
  from_state text NOT NULL,
  to_state   text NOT NULL,
  PRIMARY KEY (from_state, to_state)
);

INSERT INTO run_state_transitions_allowed (from_state, to_state) VALUES
  ('PENDING','POLICY_CHECKED'), ('PENDING','POLICY_BLOCKED'), ('PENDING','CANCELLED'), ('PENDING','FAILED'),
  ('POLICY_CHECKED','DISPATCHED'), ('POLICY_CHECKED','POLICY_BLOCKED'), ('POLICY_CHECKED','CANCELLED'), ('POLICY_CHECKED','FAILED'),
  ('DISPATCHED','OBSERVING'), ('DISPATCHED','OUTCOME_UNKNOWN'), ('DISPATCHED','CANCELLED'), ('DISPATCHED','FAILED'),
  ('OBSERVING','ANALYZING'), ('OBSERVING','OUTCOME_UNKNOWN'), ('OBSERVING','CANCELLED'), ('OBSERVING','FAILED'),
  ('OUTCOME_UNKNOWN','OBSERVING'), ('OUTCOME_UNKNOWN','FINALIZING'), ('OUTCOME_UNKNOWN','FAILED'),
  ('ANALYZING','FINALIZING'), ('ANALYZING','FAILED'),
  ('FINALIZING','CHECKPOINTED'), ('FINALIZING','FAILED'),
  ('CHECKPOINTED','EXPORTED');

CREATE FUNCTION enforce_run_state_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM run_state_transitions_allowed a
    WHERE a.from_state = NEW.from_state AND a.to_state = NEW.to_state
  ) THEN
    RAISE EXCEPTION 'ILLEGAL_TRANSITION: % -> %', NEW.from_state, NEW.to_state
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER run_state_transition_legal
  BEFORE INSERT ON run_state_transitions
  FOR EACH ROW EXECUTE FUNCTION enforce_run_state_transition();

-- ---------------------------------------------------------------------------
-- Event ledger
-- ---------------------------------------------------------------------------

-- One row per run. The ingestion service locks this row FOR UPDATE in the same
-- transaction that commits the next event, which is what makes the sequence
-- gap-free under concurrent writers (R-DAT-03).
CREATE TABLE event_stream_heads (
  run_id         uuid PRIMARY KEY REFERENCES runs(run_id),
  next_sequence  bigint  NOT NULL DEFAULT 0 CHECK (next_sequence >= 0),
  fencing_token  bigint  NOT NULL DEFAULT 0,
  finished       boolean NOT NULL DEFAULT false
);

CREATE TABLE events (
  run_id           uuid   NOT NULL REFERENCES runs(run_id),
  sequence         bigint NOT NULL CHECK (sequence >= 0),
  event_id         uuid   NOT NULL UNIQUE,
  event_type       text   NOT NULL,
  -- The exact JCS bytes, as produced by the Rust core and as signed. Never
  -- rebuilt from a JSONB column (R-PRO-04).
  canonical_bytes  bytea  NOT NULL,
  leaf_hash        bytea  NOT NULL CHECK (octet_length(leaf_hash) = 32),
  source           text   NOT NULL CHECK (source IN ('reported_by_adapter','observed_by_local_gateway','verified_by_black_box')),
  created_at_ms    bigint NOT NULL,
  PRIMARY KEY (run_id, sequence)
);

CREATE TABLE event_idempotency (
  run_id           uuid NOT NULL,
  idempotency_key  text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
  event_id         uuid NOT NULL REFERENCES events(event_id),
  PRIMARY KEY (run_id, idempotency_key)
);

CREATE TABLE workflow_outbox (
  outbox_id       bigserial PRIMARY KEY,
  run_id          uuid   NOT NULL,
  event_id        uuid   NOT NULL,
  topic           text   NOT NULL CHECK (topic IN ('sse','workflow','assessment')),
  delivered_at_ms bigint,
  attempts        integer NOT NULL DEFAULT 0
);

-- Committed events are append-only. This stops the application and an ordinary
-- role; it does not stop a superuser, and must never be described as if it did.
CREATE FUNCTION events_are_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'EVENTS_ARE_APPEND_ONLY: % on events is not allowed', TG_OP
    USING ERRCODE = 'check_violation';
END;
$$;

CREATE TRIGGER events_no_update
  BEFORE UPDATE ON events
  FOR EACH ROW EXECUTE FUNCTION events_are_append_only();

CREATE TRIGGER events_no_delete
  BEFORE DELETE ON events
  FOR EACH ROW EXECUTE FUNCTION events_are_append_only();

-- No event may follow RUN_FINISHED, and the sequence must be the one the head
-- row hands out. Both are enforced in the service transaction as well; this is
-- the belt to that braces.
CREATE FUNCTION events_respect_stream_head() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  head_finished boolean;
BEGIN
  SELECT finished INTO head_finished FROM event_stream_heads WHERE run_id = NEW.run_id;
  IF head_finished IS NULL THEN
    RAISE EXCEPTION 'NO_STREAM_HEAD for run %', NEW.run_id USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF head_finished THEN
    RAISE EXCEPTION 'RUN_FINISHED: run % accepts no more events', NEW.run_id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER events_after_finish
  BEFORE INSERT ON events
  FOR EACH ROW EXECUTE FUNCTION events_respect_stream_head();

-- ---------------------------------------------------------------------------
-- Artifacts and manifest (tables now, used in Step 6)
-- ---------------------------------------------------------------------------

CREATE TABLE artifacts (
  artifact_digest bytea PRIMARY KEY CHECK (octet_length(artifact_digest) = 32),
  media_type      text   NOT NULL,
  size_bytes      bigint NOT NULL CHECK (size_bytes >= 0),
  object_key      text   NOT NULL UNIQUE,
  status          text   NOT NULL CHECK (status IN ('PENDING','AVAILABLE','CORRUPT','ABANDONED')),
  created_at_ms   bigint NOT NULL
);

CREATE TABLE manifest_entries (
  run_id             uuid    NOT NULL REFERENCES runs(run_id),
  idx                integer NOT NULL CHECK (idx >= 0),
  event_id           uuid    NOT NULL REFERENCES events(event_id),
  artifact_digest    bytea   NOT NULL REFERENCES artifacts(artifact_digest),
  capture_method     text    NOT NULL,
  captured_at_ms     bigint  NOT NULL,
  entry_bytes        bytea   NOT NULL,
  entry_hash         bytea   NOT NULL CHECK (octet_length(entry_hash) = 32),
  prev_manifest_hash bytea   NOT NULL CHECK (octet_length(prev_manifest_hash) = 32),
  PRIMARY KEY (run_id, idx)
);

-- ---------------------------------------------------------------------------
-- Checkpoints, global log, witnesses, anchors (tables now, used in Steps 4/8)
-- ---------------------------------------------------------------------------

CREATE TABLE checkpoints (
  stream_id        text   NOT NULL,
  tree_size        bigint NOT NULL CHECK (tree_size >= 0),
  checkpoint_bytes bytea  NOT NULL,
  checkpoint_hash  bytea  NOT NULL UNIQUE CHECK (octet_length(checkpoint_hash) = 32),
  signature        bytea  NOT NULL CHECK (octet_length(signature) = 64),
  key_id           text   NOT NULL,
  created_at_ms    bigint NOT NULL,
  PRIMARY KEY (stream_id, tree_size)
);

CREATE TABLE global_log (
  position     bigint PRIMARY KEY CHECK (position >= 0),
  run_id       uuid   NOT NULL UNIQUE REFERENCES runs(run_id),
  record_bytes bytea  NOT NULL,
  leaf_hash    bytea  NOT NULL CHECK (octet_length(leaf_hash) = 32)
);

CREATE TABLE witness_signatures (
  stream_id       text   NOT NULL,
  checkpoint_hash bytea  NOT NULL REFERENCES checkpoints(checkpoint_hash),
  witness_id      text   NOT NULL,
  failure_domain  text   NOT NULL,
  signature       bytea  NOT NULL CHECK (octet_length(signature) = 64),
  received_at_ms  bigint NOT NULL,
  PRIMARY KEY (checkpoint_hash, witness_id)
);

CREATE TABLE anchor_publications (
  anchor_id       bigserial PRIMARY KEY,
  checkpoint_hash bytea  NOT NULL REFERENCES checkpoints(checkpoint_hash),
  tree_size       bigint NOT NULL,
  location        text   NOT NULL,
  anchor_domain   text   NOT NULL,
  published_at_ms bigint NOT NULL,
  evidence        text
);

-- ---------------------------------------------------------------------------
-- Assessments, approvals, disclosures, audit (tables now, used in Steps 5/9)
-- ---------------------------------------------------------------------------

CREATE TABLE assessments (
  assessment_id bigserial PRIMARY KEY,
  run_id        uuid NOT NULL REFERENCES runs(run_id),
  channel       text NOT NULL CHECK (channel IN ('POLICY','SEMANTIC','PROMPT_SECURITY','BEHAVIOR_ANOMALY')),
  event_id      uuid REFERENCES events(event_id),
  detail_json   jsonb NOT NULL,
  created_at_ms bigint NOT NULL
);

CREATE TABLE approvals (
  approval_id     uuid PRIMARY KEY,
  run_id          uuid NOT NULL REFERENCES runs(run_id),
  action_id       text NOT NULL,
  summary_digest  bytea NOT NULL CHECK (octet_length(summary_digest) = 32),
  status          text NOT NULL CHECK (status IN ('REQUESTED','GRANTED','DENIED','EXPIRED')),
  approver_key_id text REFERENCES key_manifest(key_id),
  expires_at_ms   bigint NOT NULL
);

-- Salts and clear values for committed fields. No foreign key into events on
-- purpose: deleting a salt (crypto-shredding) must not touch the ledger
-- (R-CMT-03, DESIGN.md 9.1).
CREATE TABLE field_disclosures (
  event_id   uuid NOT NULL,
  field      text NOT NULL,
  salt       bytea,
  value_json bytea,
  PRIMARY KEY (event_id, field)
);

CREATE TABLE audit_log (
  audit_id   bigserial PRIMARY KEY,
  at_ms      bigint NOT NULL,
  actor      text   NOT NULL,
  action     text   NOT NULL,
  target     text,
  request_id text,
  result     text   NOT NULL
);

-- ---------------------------------------------------------------------------
-- Indexes (starting set; tune after a benchmark, R-SVC-04)
-- ---------------------------------------------------------------------------

CREATE INDEX events_event_type_idx ON events (event_type);
CREATE INDEX workflow_outbox_undelivered_idx ON workflow_outbox (delivered_at_ms)
  WHERE delivered_at_ms IS NULL;
CREATE INDEX assessments_run_channel_idx ON assessments (run_id, channel);
CREATE INDEX witness_signatures_stream_idx ON witness_signatures (stream_id);

INSERT INTO schema_migrations (version) VALUES (1);

COMMIT;
