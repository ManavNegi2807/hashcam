"""The Postgres lease and fencing token that stand in for Temporal.

Hackathon cut (`D-13`, `R-HKC-03`): no Temporal, but the same safety rule must
hold — a worker that has been taken over MUST NOT commit afterwards
(`R-RUN-03`). The mechanism is the `fencing_token` on `event_stream_heads`:

* taking the lease increments the token and returns the new value;
* the worker sends that value as `X-Fencing-Token` on every event;
* ingestion refuses anything below the current token
  (`STALE_FENCING_TOKEN`).

What this does **not** give, stated plainly so nobody assumes otherwise:

* no lease timeout or heartbeat. A stuck worker keeps its lease until another
  worker explicitly takes over. Durable timers are what Temporal is for, and
  they are deferred (`DESIGN.md` 20.1 item 12);
* no retry policy. `ERROR_HANDLING.md` 6 forbids blindly retrying an
  irreversible action, and that decision belongs to the adapter, not here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Lease:
    """A held lease: the run, who holds it, and the token to send with events."""

    run_id: str
    worker_id: str
    fencing_token: int


class LeaseStore:
    """Lease operations against `event_stream_heads`."""

    def __init__(self, connect: Any) -> None:
        self._connect = connect

    def acquire(self, run_id: str, worker_id: str) -> Lease:
        """Take the lease for `run_id`, raising the fencing token by one.

        Monotonic by construction: the token only ever increases, so a token
        that was valid before a takeover is detectably stale afterwards.
        """
        with self._connect() as conn:
            with conn.transaction():
                row = conn.execute(
                    """UPDATE event_stream_heads
                       SET fencing_token = fencing_token + 1
                       WHERE run_id = %s
                       RETURNING fencing_token""",
                    (run_id,),
                ).fetchone()
        if row is None:
            raise LookupError(f"no stream head for run {run_id}")
        return Lease(run_id=run_id, worker_id=worker_id, fencing_token=row[0])

    def current_token(self, run_id: str) -> int | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT fencing_token FROM event_stream_heads WHERE run_id = %s", (run_id,)
            ).fetchone()
        return None if row is None else row[0]

    def holds(self, lease: Lease) -> bool:
        """True while this lease is still the newest one for its run."""
        return self.current_token(lease.run_id) == lease.fencing_token
