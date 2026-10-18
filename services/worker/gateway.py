"""The policy gateway: the only path from a proposed action to a dispatched one.

`DESIGN.md` 12, `R-POL-04`, `R-COV-07`. The shape of this class is the coverage
claim: an adapter cannot dispatch, it can only ask. Every action goes

    ACTION_REQUESTED -> ACTION_AUTHORIZED | ACTION_BLOCKED -> ACTION_DISPATCHED

and `dispatch()` refuses anything the gateway did not authorize. That refusal is
enforced here *and* checked independently by the verifier from the events
alone, because a gateway that marks its own homework proves nothing.

`REQUIRE_APPROVAL` is not an authorization. The action is recorded as
requested, the approval as requested, and nothing is dispatched until a *signed*
approval arrives (`submit_approval`). The approver's key is on their own device:
this class only relays what they signed, and the verifier re-checks it offline.

A signed **mandate**, when the run has one, is a further deterministic input. An
out-of-mandate action is blocked here, and the verifier checks the same rules
again from the events, so skipping this check is caught.
"""

from __future__ import annotations

import dataclasses
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from adapters.base import Coverage, Provenance
from policy.engine import Action, Decision, Policy
from policy.mandate import SignedMandate
from security.prompt_guard.guard import DeterministicGuard, GuardResult


@dataclass
class CommittedEvent:
    """What the ingestion service said about an event it committed."""

    event_id: str
    sequence: int
    leaf_hash: str


class GatewayError(RuntimeError):
    """The gateway could not record something, so the run must not continue."""


class Gateway:
    """Drives one run: records events, decides actions, gates dispatch."""

    def __init__(
        self,
        *,
        sink: Any,
        policy: Policy,
        provenance: Provenance,
        in_scope_actions: list[str],
        artifacts: Any = None,
        mandate: SignedMandate | None = None,
        approvals: Any = None,
        guard: DeterministicGuard | None = None,
        clock: Callable[[], int] = lambda: int(time.time() * 1000),
    ) -> None:
        self._sink = sink
        self._policy = policy
        self._provenance = provenance
        self._in_scope = in_scope_actions
        self._artifacts = artifacts
        self._authorized: set[str] = set()
        self._dispatched: set[str] = set()
        self._actions_so_far = 0
        self._mandate = mandate
        self._guard = guard
        self._worst_verdict = "ALLOW"
        self.last_screening: GuardResult | None = None
        self._trace: list[dict[str, Any]] = []
        self._approvals = approvals
        self._clock = clock
        self._mandate_authorized = 0
        self._mandate_spent = 0
        # action_id -> what the approver was asked to decide
        self._awaiting: dict[str, dict[str, Any]] = {}
        self._redacted_fields = set(policy.redaction_rules().get("ACTION_REQUESTED", []))
        self._events: list[CommittedEvent] = []

    # ------------------------------------------------------------- recording

    @property
    def events(self) -> list[CommittedEvent]:
        return list(self._events)

    def _emit(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        source: str,
        idempotency_key: str | None = None,
        with_policy_ref: bool = False,
        artifact_refs: list[str] | None = None,
    ) -> CommittedEvent:
        policy_ref = (
            {"policy_id": self._policy.policy_id, "policy_version": str(self._policy.version)}
            if with_policy_ref
            else None
        )
        committed = self._sink.emit(
            event_type=event_type,
            source=source,
            provenance=self._provenance.to_payload(),
            payload=payload,
            idempotency_key=idempotency_key,
            policy_ref=policy_ref,
            artifact_refs=artifact_refs,
        )
        event = CommittedEvent(
            event_id=committed["event_id"],
            sequence=int(committed["sequence"]),
            leaf_hash=committed["leaf_hash"],
        )
        self._events.append(event)
        # A local copy for the semantic monitor. A redacted field never goes in it.
        shown = {
            k: v
            for k, v in payload.items()
            if not (event_type == "ACTION_REQUESTED" and k in self._redacted_fields)
        }
        self._trace.append(
            {
                "event_id": event.event_id,
                "sequence": event.sequence,
                "event_type": event_type,
                "payload": shown,
            }
        )
        return event

    # --------------------------------------------------------------- lifecycle

    def run_started(self, *, task: str, requested_coverage: Coverage) -> CommittedEvent:
        payload: dict[str, Any] = {
            "task_digest": hashlib.sha256(task.encode("utf-8")).hexdigest(),
            "adapter": self._provenance.adapter_name,
            "policy_version": str(self._policy.version),
            "requested_coverage": requested_coverage,
        }
        if self._mandate is not None:
            if self._mandate.window_violation(self._clock()) is not None:
                # Both bounds are time claims, but starting outside the window
                # the human set is not something to do quietly.
                raise GatewayError("MANDATE_VIOLATION: the run is outside the mandate's window")
            payload["mandate_digest"] = self._mandate.digest
            payload["mandate_issuer_key_id"] = self._mandate.issuer_key_id
            payload["mandate_signature"] = self._mandate.signature
        return self._emit(
            "RUN_STARTED",
            payload,
            source="reported_by_adapter",
            idempotency_key="run-started",
        )

    def declare_coverage(
        self,
        *,
        requested: Coverage,
        declared: Coverage,
        reason: str,
        evidence_ref: str | None = None,
    ) -> CommittedEvent:
        """State the coverage claim, and what it covers, before acting.

        Declaring less than requested is normal and must stay visible: it is
        how the receipt stays honest (`R-COV-01`, `R-COV-05`).
        """
        return self._emit(
            "COVERAGE_DECLARED",
            {
                "requested_coverage": requested,
                "declared_coverage": declared,
                "in_scope_actions": self._in_scope,
                "reason": reason,
                # A digest of the capability test that justifies the claim (section 7).
                **({"evidence_ref": evidence_ref} if evidence_ref else {}),
            },
            source="verified_by_black_box",
            idempotency_key="coverage-declared",
        )

    def run_finished(self, *, final_state: str, outcome: str) -> CommittedEvent:
        return self._emit(
            "RUN_FINISHED",
            {
                "final_state": final_state,
                "event_count": len(self._events) + 1,
                "outcome": outcome,
            },
            source="verified_by_black_box",
            idempotency_key="run-finished",
        )

    # ------------------------------------------------------------- the gate

    def request(self, action: Action) -> Decision:
        """Record the request, decide, record the decision. No dispatch here."""
        if action.action_type not in self._in_scope:
            # Out-of-scope actions are not covered by the declared boundary, so
            # saying otherwise would be a false claim (`R-COV-01`).
            raise GatewayError(
                f"{action.action_type} is not in the declared in-scope actions {self._in_scope}"
            )

        # Fields the policy redacts travel separately and never enter a digest:
        # a hash of a low-entropy secret can be brute-forced, so the digest that
        # reaches the ledger covers only the public parameters.
        secret_params = {k: v for k, v in action.params.items() if k in self._redacted_fields}
        action = dataclasses.replace(
            action, params={k: v for k, v in action.params.items() if k not in secret_params}
        )
        requested_payload: dict[str, Any] = {
            "action_id": action.action_id,
            "action_type": action.action_type,
            "target": action.target,
            "params_digest": action.params_digest(),
            **secret_params,
        }
        if action.amount_minor_units is not None:
            requested_payload["amount_minor_units"] = action.amount_minor_units
        self._emit(
            "ACTION_REQUESTED",
            requested_payload,
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-requested",
        )

        decision = self._policy.evaluate(
            action,
            actions_so_far=self._actions_so_far,
            signals={"prompt_verdict": self._worst_verdict} if self._guard else None,
        )
        self._actions_so_far += 1
        decision = self._apply_mandate(action, decision)

        if decision.outcome == "ALLOW":
            self._count_toward_mandate(action)
            self._emit(
                "ACTION_AUTHORIZED",
                {
                    "action_id": action.action_id,
                    "policy_id": decision.policy_id,
                    "policy_version": str(decision.policy_version),
                    "decision": decision.outcome,
                    "reason_codes": list(decision.reason_codes),
                    "input_digest": decision.input_digest,
                },
                source="observed_by_local_gateway",
                idempotency_key=f"{action.action_id}-authorized",
                with_policy_ref=True,
            )
            self._authorized.add(action.action_id)
        else:
            self._emit(
                "ACTION_BLOCKED",
                {
                    "action_id": action.action_id,
                    "policy_id": decision.policy_id,
                    "policy_version": str(decision.policy_version),
                    "reason_codes": list(decision.reason_codes),
                    "input_digest": decision.input_digest,
                },
                source="observed_by_local_gateway",
                idempotency_key=f"{action.action_id}-blocked",
                with_policy_ref=True,
            )
            if decision.outcome == "REQUIRE_APPROVAL":
                # The approver has to see exactly what they are approving, so
                # the digest is over the summary, not the whole action.
                summary = self.approval_summary(action)
                approval_id = f"approval-{action.action_id}"
                digest = hashlib.sha256(summary.encode()).hexdigest()
                self._emit(
                    "HUMAN_APPROVAL_REQUESTED",
                    {
                        "action_id": action.action_id,
                        "approval_id": approval_id,
                        "summary_digest": digest,
                    },
                    source="verified_by_black_box",
                    idempotency_key=f"{action.action_id}-approval-requested",
                )
                self._awaiting[action.action_id] = {
                    "action": action,
                    "approval_id": approval_id,
                    "summary": summary,
                    "summary_digest": digest,
                    "input_digest": decision.input_digest,
                }
        return decision

    def deny(self, action: Action, reason_code: str) -> Decision:
        """Record an action an *adapter* refused before policy was asked (for example SSRF).

        It is still an ordinary request and an ordinary block, with the policy
        named and a reason code, so a receipt shows it and the verifier counts it.
        The adapter can only ever make a decision stricter this way.
        """
        if action.action_type not in self._in_scope:
            raise GatewayError(f"{action.action_type} is not in the declared in-scope actions")
        self._emit(
            "ACTION_REQUESTED",
            {
                "action_id": action.action_id,
                "action_type": action.action_type,
                "target": action.target,
                "params_digest": action.params_digest(),
            },
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-requested",
        )
        decision = Decision(
            outcome="DENY",
            reason_codes=(reason_code,),
            policy_id=self._policy.policy_id,
            policy_version=self._policy.version,
            input_digest=hashlib.sha256(
                f"{self._policy.policy_id}:{action.action_type}:{action.target}".encode()
            ).hexdigest(),
        )
        self._emit(
            "ACTION_BLOCKED",
            {
                "action_id": action.action_id,
                "policy_id": decision.policy_id,
                "policy_version": str(decision.policy_version),
                "reason_codes": list(decision.reason_codes),
                "input_digest": decision.input_digest,
            },
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-blocked",
            with_policy_ref=True,
        )
        return decision

    # ------------------------------------------------------------ the mandate

    def _apply_mandate(self, action: Action, decision: Decision) -> Decision:
        """Turn an allow into a deny if the action is outside the signed mandate."""
        if self._mandate is None or decision.outcome == "DENY":
            return decision
        reason = self._mandate.violation(
            action,
            authorized_so_far=self._mandate_authorized,
            spent_so_far=self._mandate_spent,
        )
        if reason is None:
            return decision
        return Decision(
            outcome="DENY",
            reason_codes=(reason,),
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            # What was judged: the policy's input plus the mandate that bound it.
            input_digest=hashlib.sha256(
                f"{decision.input_digest}:{self._mandate.digest}".encode()
            ).hexdigest(),
        )

    def _count_toward_mandate(self, action: Action) -> None:
        self._mandate_authorized += 1
        if action.amount_minor_units is not None:
            self._mandate_spent += action.amount_minor_units

    # ------------------------------------------------------------- approvals

    @staticmethod
    def approval_summary(action: Action) -> str:
        """Exactly what the approver is shown, and the text whose digest they sign."""
        summary = f"{action.action_type} {action.target} params={action.params_digest()}"
        readable = action.params.get("readable")
        if isinstance(readable, str) and readable:
            # Any adapter may put a sentence for the approver in `readable`. It is part of the
            # params the digest covers, and the signature covers this whole text.
            summary += " | " + readable[:200]
        if action.action_type == "payment" and action.amount_minor_units is not None:
            # A person approving money must READ the amount and who gets it, not a hash. The
            # signature covers this whole text, so what they read is what they signed.
            vendor = str(action.params.get("vendor", ""))[:80]
            currency = str(action.params.get("currency", "")).upper()[:3]
            summary += f" | PAY {action.amount_minor_units / 100:.2f} {currency} to {vendor}"
        return summary

    def pending_approvals(self) -> list[dict[str, str]]:
        """What is waiting for a human, with the text they must be shown."""
        return [
            {
                "action_id": action_id,
                "approval_id": item["approval_id"],
                "summary": item["summary"],
                "summary_digest": item["summary_digest"],
            }
            for action_id, item in self._awaiting.items()
        ]

    def submit_approval(
        self, action: Action, *, statement_b64: str, key_id: str, signature: str
    ) -> Decision:
        """Relay a signed approval; authorize the action only if it is a grant.

        The relay (the API) checks the signature against the key manifest and
        commits the event. This method then records the authorization. A denial
        authorizes nothing, and neither does an error: the action stays blocked.
        """
        pending = self._awaiting.get(action.action_id)
        if pending is None:
            raise GatewayError(f"{action.action_id} is not waiting for an approval")
        if self._approvals is None:
            raise GatewayError("no approval relay is attached to this gateway")
        answer = self._approvals.submit(
            approval_id=pending["approval_id"],
            statement_b64=statement_b64,
            key_id=key_id,
            signature=signature,
        )
        del self._awaiting[action.action_id]
        base = {
            "policy_id": self._policy.policy_id,
            "policy_version": self._policy.version,
            "input_digest": pending["input_digest"],
        }
        if answer["decision"] != "GRANTED":
            return Decision(outcome="DENY", reason_codes=("APPROVAL_DENIED",), **base)

        decision = self._apply_mandate(
            pending["action"],
            Decision(outcome="ALLOW", reason_codes=("APPROVAL_GRANTED",), **base),
        )
        if decision.outcome != "ALLOW":
            self._emit(
                "ACTION_BLOCKED",
                {
                    "action_id": action.action_id,
                    "policy_id": decision.policy_id,
                    "policy_version": str(decision.policy_version),
                    "reason_codes": list(decision.reason_codes),
                    "input_digest": decision.input_digest,
                },
                source="observed_by_local_gateway",
                idempotency_key=f"{action.action_id}-blocked-after-approval",
                with_policy_ref=True,
            )
            return decision
        self._emit(
            "ACTION_AUTHORIZED",
            {
                "action_id": action.action_id,
                "policy_id": decision.policy_id,
                "policy_version": str(decision.policy_version),
                "decision": "ALLOW",
                "reason_codes": list(decision.reason_codes),
                "input_digest": decision.input_digest,
            },
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-authorized-after-approval",
            with_policy_ref=True,
        )
        self._count_toward_mandate(pending["action"])
        self._authorized.add(action.action_id)
        return decision

    def dispatch(self, action: Action) -> CommittedEvent:
        """Record a dispatch. Refuses anything that was not authorized."""
        if action.action_id not in self._authorized:
            raise GatewayError(
                f"{action.action_id} was never authorized: the gateway will not dispatch it"
            )
        if action.action_id in self._dispatched:
            raise GatewayError(f"{action.action_id} was already dispatched")
        self._dispatched.add(action.action_id)
        return self._emit(
            "ACTION_DISPATCHED",
            {"action_id": action.action_id},
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-dispatched",
        )

    # -------------------------------------------------------- advisory channels

    def trace(self) -> list[dict[str, Any]]:
        """What the ledger holds for this run, for the semantic monitor to read.

        Read back from the ledger when the sink can, so events the control plane
        committed (a relayed approval) are included. The worker's own copy is only
        a fallback for sinks that cannot read; it lacks those events, so a monitor
        fed by it alone can wrongly report a missing approval.
        """
        fetch = getattr(self._sink, "fetch_events", None)
        if callable(fetch):
            events: list[dict[str, Any]] = fetch()
            return events
        return list(self._trace)

    #: Event types the advisory modules may write. They are advisory, so the
    #: gateway records them under the `verified_by_black_box` label and nothing else.
    ADVISORY_EVENTS = frozenset(
        {
            "SEMANTIC_INVARIANT_CHECKED",
            "SEMANTIC_VIOLATION_DETECTED",
            "PROMPT_SECURITY_ANALYSIS_COMPLETED",
            "ML_ANALYSIS_COMPLETED",
        }
    )

    def emit_advisory(
        self, event_type: str, payload: dict[str, Any], *, idempotency_key: str
    ) -> CommittedEvent:
        if event_type not in self.ADVISORY_EVENTS:
            raise GatewayError(f"{event_type} is not an advisory event")
        return self._emit(
            event_type,
            payload,
            source="verified_by_black_box",
            idempotency_key=idempotency_key,
        )

    def screen(self, text: str, *, source_kind: str, key: str) -> GuardResult | None:
        """Run the prompt guard on untrusted text and record the result (`R-PIG-01`).

        The text itself is not stored, only its digest. The verdict is a signal to
        policy, never an authorization.
        """
        if self._guard is None:
            return None
        result = self._guard.classify(text, source_kind=source_kind)
        self.emit_advisory(
            "PROMPT_SECURITY_ANALYSIS_COMPLETED", result.to_payload(), idempotency_key=key
        )
        order = {"ALLOW": 0, "FLAG_FOR_REVIEW": 1, "BLOCK_BY_POLICY": 2}
        if order[result.verdict] > order[self._worst_verdict]:
            self._worst_verdict = result.verdict
        self.last_screening = result
        return result

    # ----------------------------------------------------------- observation

    def observe(
        self, action: Action, *, observation_kind: str, url: str, text: str
    ) -> CommittedEvent:
        """Record what was seen. The text itself is not stored, only its digest.

        A digest proves the bytes match what was committed. It does not prove
        the page was truthful (`R-ART-07`).
        """
        event = self._emit(
            "BROWSER_OBSERVATION",
            {
                "action_id": action.action_id,
                "observation_kind": observation_kind,
                "url": url,
                "text_digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            },
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-observed",
        )
        # Page text is untrusted: screen it before an agent could read it.
        self.screen(text, source_kind="page_text", key=f"{action.action_id}-screened")
        return event

    def observe_api_call(
        self,
        action: Action,
        *,
        method: str,
        host: str,
        status_code: int,
        body_digest: str,
        extra: dict[str, Any] | None = None,
    ) -> CommittedEvent:
        """Record an API call this gateway made (`API_CALL_OBSERVED`).

        `extra` carries provider metering (`R-TFY-06`): execution id, usage numbers
        as returned, and when they were observed.
        """
        return self._emit(
            "API_CALL_OBSERVED",
            {
                "action_id": action.action_id,
                "method": method,
                "host": host,
                "status_code": status_code,
                "body_digest": body_digest,
                **(extra or {}),
            },
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-api-call",
        )

    def report_observation(
        self, action: Action, *, observation_kind: str, url: str, text: str
    ) -> CommittedEvent:
        """Record something an external provider **says** happened.

        Labelled `reported_by_adapter`: it is the provider's claim, not something this
        gateway saw (`PROTOCOL.md` 5.1). Text is digested, not stored.
        """
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return self._emit(
            "BROWSER_OBSERVATION",
            {
                "action_id": action.action_id,
                "observation_kind": observation_kind,
                "url": url,
                "text_digest": digest,
            },
            source="reported_by_adapter",
            idempotency_key=f"{action.action_id}-reported-{digest[:12]}",
        )

    def capture_artifact(
        self, action: Action, data: bytes, *, media_type: str, capture_method: str
    ) -> CommittedEvent:
        """Store captured bytes, announce them, then register the manifest entry.

        Order matters: the digest is needed for the event, and the manifest
        entry references the committed event. A crash between the steps leaves
        an orphan object or an event without an entry, which the reconciler of
        `ERROR_HANDLING.md` 5 is meant to resolve; that reconciler is not built.
        """
        if self._artifacts is None:
            raise GatewayError("no artifact component is attached to this run")
        stored = self._artifacts.put(data, media_type=media_type)
        event = self._emit(
            "ARTIFACT_CAPTURED",
            {
                "artifact_digest": stored.digest,
                "media_type": stored.media_type,
                "size": stored.size,
                "capture_method": capture_method,
                "manifest_index": self._artifacts.next_index,
            },
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-artifact-{stored.digest[:12]}",
            artifact_refs=[stored.digest],
        )
        self._artifacts.register(
            event_id=event.event_id, artifact=stored, capture_method=capture_method
        )
        return event

    def succeeded(self, action: Action, *, evidence: list[str]) -> CommittedEvent:
        """Record success, naming the events that are the evidence for it."""
        return self._emit(
            "ACTION_SUCCEEDED",
            {"action_id": action.action_id, "evidence_event_ids": evidence},
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-succeeded",
        )

    def failed(self, action: Action, *, error_code: str, retryable: bool) -> CommittedEvent:
        return self._emit(
            "ACTION_FAILED",
            {
                "action_id": action.action_id,
                "error_code": error_code,
                "retryable": retryable,
            },
            source="observed_by_local_gateway",
            idempotency_key=f"{action.action_id}-failed",
        )

    def outcome_unknown(self, action: Action, *, reason: str) -> CommittedEvent:
        """For a remote effect that may have happened (`ERROR_HANDLING.md` 2)."""
        return self._emit(
            "OUTCOME_UNKNOWN",
            {"action_id": action.action_id, "reason": reason},
            source="verified_by_black_box",
            idempotency_key=f"{action.action_id}-unknown",
        )
