"""The run console: a human types a task, sees the worst-case cost, says yes, and it runs.

Off unless the dashboard is started with `--enable-runs`. When on, it adds three
routes and keeps these rules:

* **A human starts every run.** Nothing is scheduled and nothing starts on its own.
  The start request must repeat the worst-case cost the page showed
  (`confirm_cents`); a lower number, or an unknown cost, is refused.
* **Only the policy's hosts.** The start site must be one the `tinyfish-demo`
  policy allows; the page offers only those.
* **Only this page can start a run.** The request needs a random token that the
  page gets from this server, the `Host` header must be the loopback address (so a
  rebinding page cannot reach it) and, if an `Origin` is sent, it must be this
  origin.
* **One run at a time**, and a run that goes past `RUN_TIMEOUT_SECONDS` is killed.
* **The API key is never read here.** The child process inherits it from the
  environment the dashboard was started in; it is not put on a command line, in a
  response or in a log. Child output is returned as-is and does not contain it.

The run itself is `tools/demo_tinyfish.py --out <receipts dir>`, so what the
console records is exactly what the demo records.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from adapters.tinyfish.budget import Budget
from adapters.tinyfish.http_client import KEY_ENV, HttpTinyFishClient
from policy.engine import Policy

REPO = Path(__file__).resolve().parents[2]
RUN_TIMEOUT_SECONDS = 300
MAX_GOAL = 500
MAX_LINES = 200
SAVED = re.compile(r"^RECEIPT_SAVED (\S+\.abbreceipt)$")
OUTCOME = re.compile(r"^RUN_OUTCOME (\w+)$")
RESULT = re.compile(r"^RESULT_TEXT (\".*\")$")
PENDING = re.compile(r"^APPROVAL_PENDING (\{.*\})$")

#: The guarded task is scripted and fixed: it runs on a fake portal with fake data.
GUARDED_TASK = "Change vendor bank details on portal.example (test site, fake data)"
RUN_TIMEOUTS = {"agent": 300, "guarded": 1200, "search": 180, "research": 1800, "realsite": 1500}
#: Modes that pause for a person's signed approval and so need a stdin to hear it on.
GATED_MODES = ("guarded", "realsite")
REALSITE_URL = "https://httpbin.org/forms/post"
#: Modes that send a question to TinyFish with no start page.
ANSWER_MODES = ("search", "research")
SIGN_KEYS = ("statement_b64", "key_id", "signature")


class Refused(Exception):
    """The request was not acted on. The message is safe to show."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Job:
    job_id: str
    started: float
    state: str = "running"  # running | done | failed
    lines: list[str] = field(default_factory=list)
    receipt: str | None = None
    goal: str = ""
    url: str = ""
    result: str | None = None
    outcome: str | None = None
    mode: str = "agent"
    pending: dict[str, str] | None = None
    approval: dict[str, str] | None = None
    proc: Any = None


def topic(goal: str) -> str:
    """A short topic for the run list, like a chat title: the task, tidied and cut at a word."""
    text = " ".join(goal.split())
    if len(text) > 48:
        text = text[:48].rsplit(" ", 1)[0].rstrip(".,;:") + "…"
    return (text[:1].upper() + text[1:]) or "Untitled task"


def _estimate() -> int | None:
    if not os.environ.get(KEY_ENV):
        return None
    return HttpTinyFishClient().estimate_cents("agent", "")


class Runner:
    def __init__(
        self,
        receipts: Path,
        *,
        python: str = sys.executable,
        budget_path: Path | None = None,
        estimate: Callable[[], int | None] = _estimate,
        command: Callable[[str, str, Path], Sequence[str]] | None = None,
        policy: Policy | None = None,
        people_dir: Path | None = None,
        abb: str | None = None,
        sign: Callable[[dict[str, str], str], dict[str, str]] | None = None,
        guarded_command: Callable[[Path], Sequence[str]] | None = None,
        estimate_answer: Callable[[str], int | None] | None = None,
        answer_command: Callable[[str, str, Path], Sequence[str]] | None = None,
        realsite_command: Callable[[str, Path], Sequence[str]] | None = None,
    ) -> None:
        self.receipts = receipts
        self.token = secrets.token_urlsafe(32)
        self._python = python
        self._budget_path = budget_path or Path(
            os.environ.get("ABB_TINYFISH_BUDGET", Path.home() / ".abb" / "tinyfish.json")
        )
        self._estimate = estimate
        self._command = command or self._default_command
        self._policy = policy or Policy.load("tinyfish-demo", 1)
        self._lock = threading.Lock()
        self._jobs: dict[str, Job] = {}
        # The approver's key lives here, in a folder the ledger API and the signer never see.
        self.people_dir = people_dir or Path(
            os.environ.get("ABB_PEOPLE_DIR", Path.home() / ".abb" / "people")
        )
        self._abb: str = abb or os.environ.get("ABB_BIN") or "abb"
        self._sign = sign or self._sign_with_abb
        self._guarded_command = guarded_command or self._default_guarded_command
        self._estimate_answer = estimate_answer or self._default_estimate_answer
        self._answer_command = answer_command or self._default_answer_command
        self._realsite_command = realsite_command or self._default_realsite_command
        if sign is None:
            self._ensure_keys()

    @property
    def hosts(self) -> list[str]:
        return sorted(self._policy.body["allowed_hosts"])

    def _default_command(self, goal: str, url: str, out: Path) -> list[str]:
        script = str(REPO / "tools" / "demo_tinyfish.py")
        return [
            self._python,
            script,
            "--goal",
            goal,
            "--url",
            url,
            "--yes-spend",
            "--out",
            str(out),
        ]

    def _spent_cents(self) -> int:
        if self._budget_path.exists():
            return Budget.load(self._budget_path).spent_cents
        return 0

    def info(self) -> dict[str, Any]:
        key_set = bool(os.environ.get(KEY_ENV))
        try:
            estimate = self._estimate() if key_set else None
        except Exception:  # a provider hiccup must not break the page
            estimate = None
        return {
            "enabled": True,
            "key_set": key_set,  # whether, never what
            "hosts": self.hosts,
            "estimate_cents": estimate,
            "spent_cents": self._spent_cents(),
            "ceiling_cents": Budget().ceiling_cents,
            "token": self.token,
            "modes": self._answer_modes(key_set),
            "realsite": {"host": "httpbin.org", "approver_key_id": self.approver_key_id()},
            "guarded": {
                "task": GUARDED_TASK,
                "approver_key_id": self.approver_key_id(),
            },
            "note": (
                "The agent runs on TinyFish's servers, not on this computer. "
                "No step cap is sent: only a 60 s limit and our deadline apply."
            ),
        }

    @staticmethod
    def check_host(host_header: str | None) -> None:
        """Only the loopback name: a page on another name pointed at 127.0.0.1 is refused."""
        host = (host_header or "").rsplit(":", 1)[0]
        if host not in {"127.0.0.1", "localhost"}:
            raise Refused("wrong host", 403)

    def check_request(self, host_header: str | None, origin: str | None, token: str | None) -> None:
        """Who is asking. Raises `Refused` for anything but this page on this computer."""
        self.check_host(host_header)
        if origin is not None and origin.split("://", 1)[-1].rsplit(":", 1)[0] not in {
            "127.0.0.1",
            "localhost",
        }:
            raise Refused("wrong origin", 403)
        if not token or not secrets.compare_digest(token, self.token):
            raise Refused("missing or wrong token", 403)

    def start(self, goal: Any, url: Any, confirm_cents: Any, mode: Any = "agent") -> str:
        if mode == "guarded":
            return self._start_guarded()
        if mode == "realsite":
            return self._start_realsite(goal)
        if mode in ANSWER_MODES:
            return self._start_answer(goal, confirm_cents, str(mode))
        if mode != "agent":
            raise Refused("unknown mode")
        if not os.environ.get(KEY_ENV):
            raise Refused(f"{KEY_ENV} is not set in the environment of this server")
        if not isinstance(goal, str) or not goal.strip() or len(goal) > MAX_GOAL:
            raise Refused(f"the task must be 1 to {MAX_GOAL} characters")
        if any(ord(c) < 32 and c not in "\n\t" for c in goal):
            raise Refused("the task has control characters")
        if not self._allowed_url(url):
            raise Refused("that start page is not allowed by the policy")
        estimate = self._estimate()
        if estimate is None:
            raise Refused("the worst-case cost is unknown, so nothing was started")
        if (
            not isinstance(confirm_cents, int)
            or isinstance(confirm_cents, bool)
            or confirm_cents < estimate
        ):
            raise Refused("the cost you confirmed is lower than the worst case; reload the page")
        with self._lock:
            if any(j.state == "running" for j in self._jobs.values()):
                raise Refused("a run is already in progress", 409)
            job = Job(job_id=uuid.uuid4().hex, started=time.time(), goal=goal, url=url)
            self._jobs[job.job_id] = job
        argv = list(self._command(goal.strip(), url, self.receipts))
        threading.Thread(target=self._drive, args=(job, argv), daemon=True).start()
        return job.job_id

    def _answer_modes(self, key_set: bool) -> dict[str, dict[str, int | None]]:
        """What search and research cost, as the wallet's rate card says (0 today)."""
        out: dict[str, dict[str, int | None]] = {}
        for mode in ANSWER_MODES:
            try:
                cents = self._estimate_answer(mode) if key_set else None
            except Exception:  # a provider hiccup must not break the page
                cents = None
            out[mode] = {"estimate_cents": cents}
        return out

    @staticmethod
    def _default_estimate_answer(mode: str) -> int | None:
        if not os.environ.get(KEY_ENV):
            return None
        return HttpTinyFishClient().estimate_cents(mode, "")

    def _default_answer_command(self, mode: str, goal: str, out: Path) -> list[str]:
        script = str(REPO / "tools" / "demo_tinyfish.py")
        return [
            self._python,
            script,
            "--mode",
            mode,
            "--goal",
            goal,
            "--yes-spend",
            "--out",
            str(out),
        ]

    def _start_answer(self, goal: Any, confirm_cents: Any, mode: str) -> str:
        """Search or research: a question sent to TinyFish's own API. There is no start page."""
        if not os.environ.get(KEY_ENV):
            raise Refused(f"{KEY_ENV} is not set in the environment of this server")
        if not isinstance(goal, str) or not goal.strip() or len(goal) > MAX_GOAL:
            raise Refused(f"the question must be 1 to {MAX_GOAL} characters")
        if any(ord(c) < 32 and c not in "\n\t" for c in goal):
            raise Refused("the question has control characters")
        estimate = self._estimate_answer(mode)
        if estimate is None:
            raise Refused("the cost is unknown, so nothing was started")
        if (
            not isinstance(confirm_cents, int)
            or isinstance(confirm_cents, bool)
            or confirm_cents < estimate
        ):
            raise Refused("the cost you confirmed is lower than the worst case; reload the page")
        with self._lock:
            if any(j.state == "running" for j in self._jobs.values()):
                raise Refused("a run is already in progress", 409)
            job = Job(job_id=uuid.uuid4().hex, started=time.time(), goal=goal, mode=mode)
            self._jobs[job.job_id] = job
        argv = list(self._answer_command(mode, goal.strip(), self.receipts))
        threading.Thread(target=self._drive, args=(job, argv), daemon=True).start()
        return job.job_id

    def _start_realsite(self, message: Any) -> str:
        """A real browser on a real site; the form submit waits for a signed approval."""
        if not isinstance(message, str) or not message.strip() or len(message) > MAX_GOAL:
            raise Refused(f"the message must be 1 to {MAX_GOAL} characters")
        if any(ord(c) < 32 and c not in "\n\t" for c in message):
            raise Refused("the message has control characters")
        with self._lock:
            if any(j.state == "running" for j in self._jobs.values()):
                raise Refused("a run is already in progress", 409)
            job = Job(
                job_id=uuid.uuid4().hex,
                started=time.time(),
                goal=message.strip(),
                url=REALSITE_URL,
                mode="realsite",
            )
            self._jobs[job.job_id] = job
        argv = list(self._realsite_command(message.strip(), self.receipts))
        threading.Thread(target=self._drive, args=(job, argv), daemon=True).start()
        return job.job_id

    def _default_realsite_command(self, message: str, out: Path) -> list[str]:
        script = str(REPO / "tools" / "demo_realsite.py")
        return [
            self._python,
            script,
            "--people-dir",
            str(self.people_dir),
            "--out",
            str(out),
            "--message",
            message,
            "--wait-seconds",
            "300",
        ]

    def _start_guarded(self) -> str:
        """The scripted risky task. Nothing here calls TinyFish, so there is no cost."""
        with self._lock:
            if any(j.state == "running" for j in self._jobs.values()):
                raise Refused("a run is already in progress", 409)
            job = Job(
                job_id=uuid.uuid4().hex,
                started=time.time(),
                goal=GUARDED_TASK,
                url="https://portal.example (fake)",
                mode="guarded",
            )
            self._jobs[job.job_id] = job
        argv = list(self._guarded_command(self.receipts))
        threading.Thread(target=self._drive, args=(job, argv), daemon=True).start()
        return job.job_id

    def _default_guarded_command(self, out: Path) -> list[str]:
        script = str(REPO / "tools" / "demo_guarded.py")
        return [
            self._python,
            script,
            "--people-dir",
            str(self.people_dir),
            "--out",
            str(out),
            "--wait-seconds",
            "300",
        ]

    # -- the approver's key: what `abb approve` does on a person's own device

    def _ensure_keys(self) -> None:
        for role in ("approver", "mandate_issuer"):
            if (self.people_dir / f"{role}.key").exists():
                continue
            try:
                self.people_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(  # noqa: S603 - fixed argv
                    [self._abb, "keygen", "--out", str(self.people_dir), "--role", role],
                    capture_output=True,
                    check=True,
                    timeout=30,
                )
            except (OSError, subprocess.SubprocessError):
                return  # guarded runs will then fail with a clear message

    def approver_key_id(self) -> str | None:
        """The public id of the approver's key. Never the key itself."""
        try:
            public = (self.people_dir / "approver.pub").read_text(encoding="utf-8").strip()
            return "ed25519:" + hashlib.sha256(bytes.fromhex(public)).hexdigest()
        except (OSError, ValueError):
            return None

    def _sign_with_abb(self, pending: dict[str, str], decision: str) -> dict[str, str]:
        """Sign with `abb approve`. The CLI refuses unless the summary hashes to the digest."""
        expires_at = int(time.time() * 1000) + 600_000
        done = subprocess.run(  # noqa: S603 - fixed argv, values validated before
            [
                self._abb,
                "approve",
                "--key",
                str(self.people_dir / "approver.key"),
                "--run-id",
                pending["run_id"],
                "--action-id",
                pending["action_id"],
                "--approval-id",
                pending["approval_id"],
                "--decision",
                decision,
                "--expires-at",
                str(expires_at),
                "--summary",
                pending["summary"],
                "--summary-digest",
                pending["summary_digest"],
            ],
            capture_output=True,
            check=True,
            timeout=30,
        )
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )
        return {k: fields[k] for k in SIGN_KEYS}

    def approve(self, job_id: Any, decision: Any, summary_digest: Any) -> dict[str, str]:
        """A person's click. Signs exactly what they were shown, or refuses."""
        job = self._jobs.get(job_id) if isinstance(job_id, str) else None
        if job is None:
            raise Refused("no such run", 404)
        if decision not in ("GRANTED", "DENIED"):
            raise Refused("the decision must be GRANTED or DENIED")
        with self._lock:
            pending = job.pending
            if pending is None or job.state != "running" or job.proc is None:
                raise Refused("nothing is waiting for approval", 409)
            if not isinstance(summary_digest, str) or not secrets.compare_digest(
                summary_digest, pending["summary_digest"]
            ):
                raise Refused("what you saw is not what is waiting; reload the page", 409)
            job.pending = None  # claimed: a second click cannot sign it again
        try:
            signed = self._sign(pending, str(decision))
            line = json.dumps({k: signed[k] for k in SIGN_KEYS}) + chr(10)
            job.proc.stdin.write(line)
            job.proc.stdin.flush()
        except (OSError, KeyError, subprocess.SubprocessError, ValueError):
            job.pending = pending  # nothing was sent; the person can try again
            raise Refused("could not sign or deliver the approval", 500) from None
        job.approval = {"decision": str(decision), "key_id": signed["key_id"]}
        return job.approval

    def _drive(self, job: Job, argv: list[str]) -> None:
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv built here from validated values
                argv,
                cwd=str(REPO),
                env={
                    **os.environ,
                    "PYTHONPATH": str(REPO),
                    "PYTHONUNBUFFERED": "1",
                    "PYTHONUTF8": "1",  # answers hold characters a console encoding cannot print
                    "PYTHONIOENCODING": "utf-8",
                },
                stdin=subprocess.PIPE if job.mode in GATED_MODES else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            job.lines.append("could not start the run")
            job.state = "failed"
            return
        job.proc = proc
        timeout = RUN_TIMEOUTS.get(job.mode, RUN_TIMEOUT_SECONDS)
        killer = threading.Timer(timeout, proc.kill)
        killer.start()
        try:
            if proc.stdout is None:  # pragma: no cover
                raise OSError("no output pipe")
            for raw in proc.stdout:
                full = raw.rstrip()
                line = full[:2000]  # only the log is shortened, never the answer line
                match = SAVED.match(line)
                if match:
                    job.receipt = match.group(1)
                waiting = PENDING.match(full)
                if waiting:
                    job.pending = self._clean_pending(waiting.group(1))
                    job.lines.append("waiting for your approval")
                    continue
                outcome = OUTCOME.match(line)
                if outcome:
                    job.outcome = outcome.group(1)
                answer = RESULT.match(full)
                if answer:
                    try:
                        job.result = str(json.loads(answer.group(1)))[:4000]
                    except ValueError:
                        job.lines.append("the answer line could not be read")
                    continue  # shown as the answer, not repeated in the log
                if len(job.lines) < MAX_LINES:
                    job.lines.append(line)
            code = proc.wait()
        finally:
            killer.cancel()
        job.state = "done" if code == 0 and job.receipt else "failed"
        if job.receipt:
            self._write_label(job)
        if code != 0:
            job.lines.append(f"the run ended with exit code {code}")

    @staticmethod
    def _clean_pending(raw: str) -> dict[str, str] | None:
        """The approval request from the script, accepted only if every field is text."""
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        keys = ("run_id", "action_id", "approval_id", "summary", "summary_digest")
        if not isinstance(data, dict) or not all(isinstance(data.get(k), str) for k in keys):
            return None
        return {k: str(data[k])[:2000] for k in keys}

    def _allowed_url(self, url: Any) -> bool:
        """https, no login part, and a host the policy allows. A path is fine."""
        if not isinstance(url, str) or len(url) > 300 or any(c.isspace() for c in url):
            return False
        parts = urlparse(url)
        return (
            parts.scheme == "https"
            and parts.username is None
            and parts.password is None
            and parts.hostname in self.hosts
            and not parts.fragment
        )

    def _write_label(self, job: Job) -> None:
        """A readable name for the run list. This file sits beside the receipt, outside it:
        the receipt itself still holds only the task's hash."""
        title = topic("Real form: " + job.goal if job.mode == "realsite" else job.goal)
        label = {
            "title": title,
            "goal": job.goal.strip()[:500],
            "url": job.url,
            "mode": job.mode,
            "started_at": int(job.started),
        }
        if job.approval:
            label["approval"] = job.approval
        if job.result:
            label["answer"] = job.result[:2000]
        try:
            (self.receipts / (job.receipt or "")).with_name(
                (job.receipt or "") + ".meta.json"
            ).write_text(json.dumps(label), encoding="utf-8")
        except OSError:
            pass  # the list falls back to the date

    def status(self, job_id: str) -> dict[str, Any]:
        job = self._jobs.get(job_id)
        if job is None:
            raise Refused("no such run", 404)
        return {
            "state": job.state,
            "lines": job.lines[-60:],
            "receipt": job.receipt,
            "result": job.result,
            "outcome": job.outcome,
            "mode": job.mode,
            "pending": (
                {k: job.pending[k] for k in ("action_id", "summary", "summary_digest")}
                if job.pending
                else None
            ),
            "approval": job.approval,
            "seconds": int(time.time() - job.started),
        }
