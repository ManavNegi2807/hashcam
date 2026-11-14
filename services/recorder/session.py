"""One recorded agent session: the browser extension's reports turned into a signed run.

The extension watches a tab that another AI agent drives. It reports what the agent does; this
module puts each report through the **existing** policy gateway (`services/worker/gateway.py`),
so the same events, signatures and offline checks apply as for every other HashCam run.

* The **passport** is a signed mandate (`policy/mandate.py`): allowed sites, a spend bound and an
  expiry, signed with the mandate-issuer key. The gateway blocks anything outside it, and the
  verifier re-checks the same rules from the events.
* **Approvals** are signed with the person's approver key through `abb approve`. The side panel
  first asks for a passkey (fingerprint, face or PIN); without a valid passkey answer the key is
  not used. See `passkey.py` for what that does and does not prove.
* The **tripwire** is the existing prompt guard (page text) plus a task-drift rule. Both are
  advisory: they are recorded, they never allow anything.
* **Secrets** arrive as salted commitments computed inside the page. The value never leaves it.

Coverage is `STEP_OBSERVED`, never `STEP_GATED`: a browser extension sees navigations, form
submissions and downloads, but an agent can still send data with a script (`fetch`, WebSocket)
that this extension does not intercept.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adapters.base import Provenance
from policy.engine import Action, Policy, host_matches, host_of
from security.prompt_guard.guard import DeterministicGuard
from services.api.canonical import Canonicalizer
from services.api.repository import Repository
from services.artifacts.component import ArtifactComponent
from services.recorder import passkey
from services.worker.approval_client import HttpApprovalClient
from services.worker.event_sink import HttpEventSink
from services.worker.gateway import Gateway
from services.worker.lease import LeaseStore
from tools import demo

ADAPTER = "hashcam-recorder"
ADAPTER_VERSION = "0.1.0"
IN_SCOPE = ["navigate", "form_fill", "form_submit", "download"]
COVERAGE_REASON = (
    "a browser extension observes navigations, form submissions and downloads in one tab; "
    "requests a page script sends itself (fetch, XHR, WebSocket) are not intercepted"
)
DRIFT_MODEL = "task-drift"
#: How long an approval card waits before the action is left unsent.
DEFAULT_APPROVAL_SECONDS = 120
MAX_TEXT = 200_000
MAX_SNAPSHOT = 4_000_000

_HOSTLIKE = re.compile(r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b", re.IGNORECASE)


class RecorderError(Exception):
    """A request the recorder refuses. The message is safe to show."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Pending:
    action: Action
    approval_id: str
    summary: str
    summary_digest: str
    deadline: float


@dataclass
class Session:
    session_id: str
    run_id: str
    task: str
    agent: str
    passport: dict[str, Any]
    gateway: Gateway
    repo: Repository
    started: float
    task_hosts: list[str]
    timeline: list[dict[str, Any]] = field(default_factory=list)
    pending: dict[str, Pending] = field(default_factory=dict)
    snapshots: dict[int, bytes] = field(default_factory=dict)
    counter: int = 0
    state: str = "recording"
    receipt: str | None = None
    verdict: dict[str, Any] | None = None
    lock: threading.Lock = field(default_factory=threading.Lock)


class Recorder:
    """The signer, the ledger API and the sessions, on this computer only."""

    def __init__(
        self,
        *,
        stack: demo.Stack,
        tokens: dict[str, str],
        receipts: Path,
        approval_seconds: int = DEFAULT_APPROVAL_SECONDS,
    ) -> None:
        self.stack = stack
        self.tokens = tokens
        self.receipts = receipts
        self.policy = Policy.load("recorder", 1)
        self.approval_seconds = approval_seconds
        self.base_url = f"http://127.0.0.1:{stack.api_port}"
        self.sessions: dict[str, Session] = {}
        self.credential: passkey.Credential | None = None
        self._challenges: dict[str, str] = {}
        self._lock = threading.Lock()
        receipts.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- setup

    @classmethod
    def start(
        cls, *, admin_dsn: str, work: Path, receipts: Path, people: Path | None = None, **kw: Any
    ) -> Recorder:
        """Make a fresh ledger database, start the signer and the API, return the recorder."""
        from pathsafe import read_migrations

        policy = Policy.load("recorder", 1)
        dsn = demo.prepare_database(admin_dsn, read_migrations(demo.REPO / "deploy" / "migrations"))
        tokens = demo.seed(dsn, policy)
        stack = demo.Stack(
            work=work,
            dsn=dsn,
            abb=demo.binary("abb", "ABB_BIN"),
            signer_bin=demo.binary("abb-signer", "ABB_SIGNER_BIN"),
            signer_port=demo.free_port(),
            api_port=demo.free_port(),
            people=people,
        )
        demo.start_stack(stack)
        return cls(stack=stack, tokens=tokens, receipts=receipts, **kw)

    def close(self) -> None:
        self.stack.stop()

    # ------------------------------------------------------------- passkeys

    def passkey_challenge(self, purpose: str, *, decision: str = "", digest: str = "") -> str:
        """A challenge for registration (random) or for one approval (bound to what was shown)."""
        if purpose == "register":
            challenge = passkey.new_challenge()
        elif purpose == "approve":
            challenge = passkey.approval_challenge(decision, digest)
        else:
            raise RecorderError("unknown passkey purpose")
        with self._lock:
            self._challenges[purpose] = challenge
        return challenge

    def passkey_register(self, payload: dict[str, Any], origin: str) -> None:
        with self._lock:
            challenge = self._challenges.pop("register", None)
        if challenge is None:
            raise RecorderError("ask for a registration challenge first", 409)
        try:
            self.credential = passkey.register(payload, challenge=challenge, origin=origin)
        except passkey.PasskeyError as exc:
            raise RecorderError(str(exc)) from None

    # -------------------------------------------------------------- sessions

    def start_session(self, *, task: str, agent: str, passport: dict[str, Any]) -> Session:
        task = str(task).strip()[:500]
        agent = str(agent).strip()[:60] or "AI agent"
        if not task:
            raise RecorderError("say what the agent was asked to do")
        hosts = [str(h).strip().lower() for h in passport.get("hosts", []) if str(h).strip()]
        if not hosts or not all(re.fullmatch(r"(\*\.)?[a-z0-9.-]+", h) for h in hosts):
            raise RecorderError("the passport needs at least one site, like example.com")
        minutes = int(passport.get("minutes", 30))
        if not 1 <= minutes <= 24 * 60:
            raise RecorderError("the passport must expire within a day")
        spend = int(passport.get("max_spend_minor_units", 0))
        now = int(time.time() * 1000)
        mandate = demo.signed_mandate(
            self.stack,
            subject=ADAPTER,
            allowed_hosts=hosts,
            allowed_action_types=list(IN_SCOPE),
            max_actions=10_000,
            # The core accepts a spend bound only together with its currency.
            max_spend_minor_units=spend if spend > 0 else None,
            currency=str(passport.get("currency", "USD"))[:3].upper() if spend > 0 else None,
            not_before=now - 60_000,
            not_after=now + minutes * 60_000,
        )
        mandate_id = demo.register_mandate(self.base_url, self.tokens["operator"], mandate)
        run_id = demo.create_run(
            self.base_url,
            self.tokens["operator"],
            self.policy,
            mandate_id=mandate_id,
            adapter=ADAPTER,
            task=task,
        )
        lease = LeaseStore(demo.connections(self.stack.dsn)).acquire(run_id, "recorder")
        sink = HttpEventSink(
            base_url=self.base_url,
            run_id=run_id,
            token=self.tokens["adapter"],
            fencing_token=lease.fencing_token,
        )
        repo = Repository(
            connect=demo.connections(self.stack.dsn), canonicalizer=Canonicalizer(self.stack.abb)
        )
        session_id = uuid.uuid4().hex[:12]
        gateway = Gateway(
            sink=sink,
            policy=self.policy,
            provenance=Provenance(
                ADAPTER, ADAPTER_VERSION, f"rec-{session_id}", "LIVE_LOCAL", "STEP_OBSERVED"
            ),
            in_scope_actions=list(IN_SCOPE),
            artifacts=ArtifactComponent(
                store=demo.artifact_store(self.stack), repository=repo, run_id=run_id
            ),
            mandate=mandate,
            approvals=HttpApprovalClient(
                base_url=self.base_url, run_id=run_id, token=self.tokens["adapter"]
            ),
            guard=DeterministicGuard(),
        )
        gateway.run_started(task=task, requested_coverage="STEP_OBSERVED")
        gateway.declare_coverage(
            requested="STEP_OBSERVED", declared="STEP_OBSERVED", reason=COVERAGE_REASON
        )
        session = Session(
            session_id=session_id,
            run_id=run_id,
            task=task,
            agent=agent,
            passport={
                "hosts": hosts,
                "minutes": minutes,
                "max_spend_minor_units": spend,
                "expires_at": now + minutes * 60_000,
                "mandate_id": mandate_id,
            },
            gateway=gateway,
            repo=repo,
            started=time.time(),
            task_hosts=sorted({m.lower() for m in _HOSTLIKE.findall(task)}),
        )
        with self._lock:
            self.sessions[session_id] = session
        self._note(session, "SESSION", "", "RECORDING", [f"passport: {', '.join(hosts)}"])
        return session

    def get(self, session_id: Any) -> Session:
        session = self.sessions.get(session_id) if isinstance(session_id, str) else None
        if session is None:
            raise RecorderError("no such session", 404)
        return session

    # ---------------------------------------------------------------- events

    def report(self, session: Session, body: dict[str, Any]) -> dict[str, Any]:
        """One thing the agent is about to do, or did. Returns what the extension must do."""
        kind = body.get("kind")
        url = str(body.get("url", ""))[:2000]
        if kind not in ("navigate", "form_submit", "download", "secret"):
            raise RecorderError("unknown event kind")
        if host_of(url) is None:
            raise RecorderError("the event needs an http(s) address")
        with session.lock:
            if session.state != "recording":
                raise RecorderError("this session has stopped", 409)
            self._expire(session)
            session.counter += 1
            action_id = f"{kind.replace('_', '-')}-{session.counter}"
            if kind == "secret":
                return self._secret(session, action_id, url, body)
            readable = self._readable(session, kind, url, body)
            action = Action(
                action_id=action_id,
                action_type=kind,
                target=url,
                params={"readable": readable, "agent": session.agent},
            )
            decision = session.gateway.request(action)
            drift = self._drift(session, action)
            reasons = list(decision.reason_codes)
            if decision.outcome == "ALLOW":
                session.gateway.dispatch(action)
                self._note(session, kind, url, "ALLOWED", reasons, action_id=action_id, drift=drift)
                return {
                    "action_id": action_id,
                    "decision": "ALLOW",
                    "reasons": reasons,
                    "drift": drift,
                }
            if decision.outcome == "REQUIRE_APPROVAL":
                waiting = next(
                    p for p in session.gateway.pending_approvals() if p["action_id"] == action_id
                )
                session.pending[action_id] = Pending(
                    action=action,
                    approval_id=waiting["approval_id"],
                    summary=waiting["summary"],
                    summary_digest=waiting["summary_digest"],
                    deadline=time.time() + self.approval_seconds,
                )
                self._note(session, kind, url, "WAITING", reasons, action_id=action_id, drift=drift)
                return {
                    "action_id": action_id,
                    "decision": "NEEDS_APPROVAL",
                    "reasons": reasons,
                    "drift": drift,
                    "summary": waiting["summary"],
                    "summary_digest": waiting["summary_digest"],
                    "expires_in": self.approval_seconds,
                }
            self._note(session, kind, url, "BLOCKED", reasons, action_id=action_id, drift=drift)
            return {"action_id": action_id, "decision": "DENY", "reasons": reasons, "drift": drift}

    def observe(self, session: Session, body: dict[str, Any]) -> dict[str, Any]:
        """What the page showed after an allowed navigation: text (screened) and a snapshot."""
        action_id = str(body.get("action_id", ""))
        with session.lock:
            entry = next((e for e in session.timeline if e.get("action_id") == action_id), None)
            if entry is None or entry["kind"] != "navigate" or entry["status"] != "ALLOWED":
                raise RecorderError("only an allowed page load can be observed", 409)
            if entry.get("observed"):
                raise RecorderError("this page load was already observed", 409)
            action = Action(action_id=action_id, action_type="navigate", target=entry["target"])
            text = str(body.get("text", ""))[:MAX_TEXT]
            seen = session.gateway.observe(
                action, observation_kind="page_text", url=entry["target"], text=text
            )
            evidence = [seen.event_id]
            screening = session.gateway.last_screening
            tripwire = None
            if screening is not None and screening.verdict != "ALLOW":
                tripwire = {"verdict": screening.verdict, "reasons": list(screening.reason_codes)}
            snapshot = self._snapshot(body.get("snapshot_png_b64"))
            if snapshot is not None:
                captured = session.gateway.capture_artifact(
                    action, snapshot, media_type="image/png", capture_method="extension-tab-capture"
                )
                evidence.append(captured.event_id)
                entry["snapshot"] = len(session.snapshots)
                session.snapshots[entry["snapshot"]] = snapshot
            session.gateway.succeeded(action, evidence=evidence)
            entry["observed"] = True
            entry["tripwire"] = tripwire
            entry["leaf"] = session.gateway.events[-1].leaf_hash
            return {"tripwire": tripwire}

    def decide(self, session: Session, body: dict[str, Any]) -> dict[str, Any]:
        """A person's decision on a waiting action, unlocked by their passkey."""
        action_id = str(body.get("action_id", ""))
        choice = body.get("decision")
        if choice not in ("GRANTED", "DENIED"):
            raise RecorderError("the decision must be GRANTED or DENIED")
        if self.credential is None:
            raise RecorderError("register a passkey first", 409)
        with session.lock:
            self._expire(session)
            pending = session.pending.get(action_id)
            if pending is None:
                raise RecorderError("nothing is waiting under that id (it may have timed out)", 409)
            if body.get("summary_digest") != pending.summary_digest:
                raise RecorderError("what you saw is not what is waiting; reload", 409)
            try:
                passkey.verify_assertion(
                    self.credential,
                    body.get("passkey") or {},
                    challenge=passkey.approval_challenge(choice, pending.summary_digest),
                )
            except passkey.PasskeyError as exc:
                raise RecorderError(f"passkey not accepted: {exc}", 403) from None
            del session.pending[action_id]
            signed = demo.sign_approval(
                self.stack,
                {
                    "action_id": action_id,
                    "approval_id": pending.approval_id,
                    "summary": pending.summary,
                    "summary_digest": pending.summary_digest,
                },
                session.run_id,
                decision=choice,
            )
            answer = session.gateway.submit_approval(
                pending.action,
                statement_b64=signed["statement_b64"],
                key_id=signed["key_id"],
                signature=signed["signature"],
            )
            entry = self._entry(session, action_id)
            if answer.outcome == "ALLOW":
                session.gateway.dispatch(pending.action)
                entry.update(status="APPROVED", sealed=True)
            else:
                entry.update(status="DENIED", sealed=True)
            entry["reasons"] = list(answer.reason_codes)
            entry["leaf"] = session.gateway.events[-1].leaf_hash
            return {
                "action_id": action_id,
                "decision": answer.outcome,
                "reasons": list(answer.reason_codes),
            }

    def stop(self, session: Session, *, killed: bool) -> dict[str, Any]:
        """Kill switch or normal end: seal the run, export the receipt, verify it offline."""
        with session.lock:
            if session.state != "recording":
                return {"receipt": session.receipt, "verdict": session.verdict}
            session.state = "sealing"
            for action_id in list(session.pending):
                self._entry(session, action_id).update(status="NOT_SENT")
            session.pending.clear()
            outcome = "KILLED_BY_USER" if killed else "COMPLETED"
            session.gateway.run_finished(final_state="FINALIZING", outcome=outcome)
            session.repo.set_state(session.run_id, "FINALIZING")
            exported = demo.finalize_and_export(self.stack, session.run_id, self.policy)
            name = f"recorder-{session.session_id}.abbreceipt"
            shutil.copyfile(exported, self.receipts / name)
            shutil.copyfile(demo.key_manifest(self.stack), self.receipts / (name + ".keys.json"))
            (self.receipts / (name + ".meta.json")).write_text(
                json.dumps(
                    {
                        "title": f"{session.agent}: {session.task}"[:120],
                        "mode": "recorder",
                        "started_at": int(session.started),
                    }
                ),
                encoding="utf-8",
            )
            session.receipt = name
            session.verdict = self.verify(self.receipts / name)
            session.state = "sealed"
            self._note(
                session,
                "SEALED",
                "",
                session.verdict.get("overall", "?"),
                ["kill switch" if killed else "stopped"],
            )
            return {"receipt": name, "verdict": session.verdict}

    def verify(self, path: Path) -> dict[str, Any]:
        """The offline verifier's own verdict. The recorder never decides validity itself."""
        from services.dashboard.server import Config
        from services.dashboard.server import verify as run_verifier

        keys = path.with_name(path.name + ".keys.json")
        return run_verifier(
            Config(receipts=path.parent, keys=keys if keys.exists() else None, abb=self.stack.abb),
            path,
        )

    # ---------------------------------------------------------------- views

    def view(self, session: Session) -> dict[str, Any]:
        with session.lock:
            self._expire(session)
            return {
                "session_id": session.session_id,
                "run_id": session.run_id,
                "agent": session.agent,
                "task": session.task,
                "passport": session.passport,
                "state": session.state,
                "started": session.started,
                "timeline": [dict(e) for e in session.timeline],
                "waiting": [
                    {
                        "action_id": a,
                        "summary": p.summary,
                        "summary_digest": p.summary_digest,
                        "seconds_left": max(0, int(p.deadline - time.time())),
                    }
                    for a, p in session.pending.items()
                ],
                "receipt": session.receipt,
                "verdict": session.verdict,
                "trust": self._trust(session),
            }

    # -------------------------------------------------------------- helpers

    def _secret(
        self, session: Session, action_id: str, url: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        """A typed password or card number, as a salted commitment made inside the page."""
        commitment = str(body.get("commitment", ""))
        field_kind = body.get("field_kind")
        if not re.fullmatch(r"[0-9a-f]{64}", commitment) or field_kind not in ("password", "card"):
            raise RecorderError("a secret is reported as a 64-hex commitment and a field kind")
        action = Action(
            action_id=action_id,
            action_type="form_fill",
            target=url,
            params={"field_kind": field_kind, "commitment": commitment},
        )
        decision = session.gateway.request(action)
        if decision.outcome == "ALLOW":
            session.gateway.dispatch(action)
        status = "COMMITTED" if decision.outcome == "ALLOW" else "BLOCKED"
        self._note(
            session,
            "secret",
            url,
            status,
            list(decision.reason_codes),
            action_id=action_id,
            field_kind=field_kind,
        )
        return {
            "action_id": action_id,
            "decision": decision.outcome,
            "reasons": list(decision.reason_codes),
        }

    @staticmethod
    def _readable(session: Session, kind: str, url: str, body: dict[str, Any]) -> str:
        host = host_of(url) or url
        if kind == "form_submit":
            fields = [str(f)[:40] for f in body.get("fields", []) if isinstance(f, str)][:12]
            what = f" (fields: {', '.join(fields)})" if fields else ""
            return f"{session.agent} wants to submit a form to {host}{what}"
        if kind == "download":
            filename = str(body.get("filename", ""))[:80]
            return f"{session.agent} wants to download {filename} from {host}"
        return f"{session.agent} opens {host}"

    def _drift(self, session: Session, action: Action) -> dict[str, Any] | None:
        """Advisory: the task names sites, and this action goes somewhere else."""
        host = host_of(action.target)
        if not session.task_hosts or host is None:
            return None
        if any(host_matches(host, h) or host_matches(host, "*." + h) for h in session.task_hosts):
            return None
        session.gateway.emit_advisory(
            "ML_ANALYSIS_COMPLETED",
            {
                "model_id": DRIFT_MODEL,
                "model_version": "1",
                "feature_schema_id": "task-hosts-v1",
                "score_ppm": 1_000_000,
                "reason_codes": ["HOST_NOT_IN_TASK"],
                "score_kind": "RULE_SUM",
                "threshold_ppm": 500_000,
            },
            idempotency_key=f"{action.action_id}-drift",
        )
        return {"reason": "HOST_NOT_IN_TASK", "host": host, "task_hosts": session.task_hosts}

    def _snapshot(self, raw: Any) -> bytes | None:
        if not isinstance(raw, str) or not raw:
            return None
        try:
            data = base64.b64decode(raw, validate=True)
        except ValueError:
            raise RecorderError("the snapshot is not base64") from None
        if len(data) > MAX_SNAPSHOT or not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise RecorderError("the snapshot must be a PNG under 4 MB")
        return data

    def _expire(self, session: Session) -> None:
        """An approval nobody answered in time leaves the action unsent, for good."""
        now = time.time()
        for action_id, pending in list(session.pending.items()):
            if pending.deadline <= now:
                del session.pending[action_id]
                self._entry(session, action_id).update(status="TIMED_OUT")

    @staticmethod
    def _entry(session: Session, action_id: str) -> dict[str, Any]:
        return next(e for e in session.timeline if e.get("action_id") == action_id)

    def _note(
        self,
        session: Session,
        kind: str,
        target: str,
        status: str,
        reasons: list[str],
        **extra: Any,
    ) -> None:
        events = session.gateway.events
        session.timeline.append(
            {
                "n": len(session.timeline) + 1,
                "at": time.time(),
                "kind": kind,
                "target": target,
                "status": status,
                "reasons": reasons,
                "leaf": events[-1].leaf_hash if events else None,
                **extra,
            }
        )

    @staticmethod
    def _trust(session: Session) -> int:
        """A simple, explained track record (0-100): blocked, drift and tripwire lower it.

        Shown as a gauge. It is a summary of this session's own events, not a verdict.
        """
        score = 100
        for e in session.timeline:
            if e["status"] == "BLOCKED":
                score -= 20
            if e.get("drift"):
                score -= 15
            if e.get("tripwire"):
                score -= 25 if e["tripwire"]["verdict"] == "BLOCK_BY_POLICY" else 10
        return max(0, score)
