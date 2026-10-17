"""A hard spending ceiling, driven by what the provider reports (`R-TFY-03`..`R-TFY-05`).

The ceiling counts **metered usage the provider returned**, not requests made:
guessing from a request count would be a guess dressed as a limit. Amounts are
integer cents, because protocol numbers are integers.

Two rules, and no third:

* optional calls stop when the *reserve* would be reached, not when the money is
  gone, so there is always something left to finish or investigate with;
* there is **no paid fallback**. Nothing in this module or the adapter retries a
  failed or refused call by some other, costlier route (`R-TFY-05`).

The planning split of the first $15 (`R-TFY-09`) is a planning aid. It is not a
provider price estimate and nothing here claims what any call costs.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

#: $15.00 in cents, and the planned split. Planning limits, not prices.
CEILING_CENTS = 1500
ALLOCATION_CENTS = {"agent": 600, "search_fetch": 300, "validation": 300, "reserve": 300}


class BudgetError(Exception):
    """Base class: a call was refused before it was made."""

    code = "BUDGET_ERROR"


class BudgetReserveReached(BudgetError):
    """Spending one more call would eat into the reserve. Optional calls stop here."""

    code = "BUDGET_RESERVE_REACHED"


class CeilingReached(BudgetError):
    """Nothing is left. No call of any kind is made."""

    code = "PROVIDER_QUOTA_EXHAUSTED"


@dataclass
class Budget:
    """The project-wide ceiling. `path`, when given, makes it survive restarts."""

    ceiling_cents: int = CEILING_CENTS
    reserve_cents: int = ALLOCATION_CENTS["reserve"]
    spent_cents: int = 0
    path: Path | None = None

    @classmethod
    def load(cls, path: Path, **kwargs: int) -> Budget:
        """Read the spend so far from `path` (a restart must not reset the ceiling)."""
        spent = 0
        if path.exists():
            spent = int(json.loads(path.read_text(encoding="utf-8"))["spent_cents"])
        return cls(spent_cents=spent, path=path, **kwargs)

    @property
    def remaining_cents(self) -> int:
        return self.ceiling_cents - self.spent_cents

    def check(self, estimate_cents: int | None) -> None:
        """Refuse before the call. With no estimate the next call is assumed to cost at
        least one cent: an unknown cost is not a free one."""
        cost = estimate_cents if estimate_cents is not None else 1
        if self.remaining_cents <= 0 or cost > self.remaining_cents:
            raise CeilingReached("the spending ceiling is reached")
        if self.remaining_cents - cost < self.reserve_cents:
            raise BudgetReserveReached("this call would reach the reserve")

    def record(self, metered_cents: int) -> None:
        """Add what the provider says it charged. Never negative, never lowered."""
        if metered_cents < 0:
            raise ValueError("metered usage cannot be negative")
        self.spent_cents += metered_cents
        if self.path is not None:
            temp = self.path.with_suffix(".tmp")
            temp.write_text(json.dumps({"spent_cents": self.spent_cents}), encoding="utf-8")
            os.replace(temp, self.path)
