-- Step 9: keep the approver's own signature, not just the control plane's
-- event about it. The receipt needs the signed statement so a verifier can
-- check the approval without trusting the control plane (PROTOCOL.md 5.6).
--
-- Forward-only. The relay never holds an approver key: it stores what the
-- approver's device produced, and the verifier checks it again offline.

CREATE TABLE signed_approvals (
  run_id          uuid NOT NULL REFERENCES runs(run_id),
  approval_id     text NOT NULL,
  action_id       text NOT NULL,
  decision        text NOT NULL CHECK (decision IN ('GRANTED','DENIED')),
  statement       bytea NOT NULL,
  approver_key_id text NOT NULL,
  signature       text NOT NULL CHECK (signature ~ '^[0-9a-f]{128}$'),
  event_id        uuid NOT NULL,
  created_at_ms   bigint NOT NULL,
  PRIMARY KEY (run_id, approval_id)
);

-- A signed statement, once stored, is not edited or removed. This stops the
-- application and an ordinary role; it does not stop a superuser.
CREATE FUNCTION signed_approvals_are_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'SIGNED_APPROVALS_ARE_APPEND_ONLY: % is not allowed', TG_OP
    USING ERRCODE = 'check_violation';
END;
$$;

CREATE TRIGGER signed_approvals_no_update
  BEFORE UPDATE ON signed_approvals
  FOR EACH ROW EXECUTE FUNCTION signed_approvals_are_append_only();

CREATE TRIGGER signed_approvals_no_delete
  BEFORE DELETE ON signed_approvals
  FOR EACH ROW EXECUTE FUNCTION signed_approvals_are_append_only();

INSERT INTO schema_migrations (version) VALUES (2);
