# payment.py: payment ka pura raasta. Agent sirf request banata hai, paisa nahi bhejta.
# Asli signing user ke testnet wallet se hogi, yahan signer ek function hai jo bahar se aata hai.
import sqlite3
import time
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS payments (
    payment_id   TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    amount_inr   INTEGER NOT NULL,
    site         TEXT NOT NULL,
    status       TEXT NOT NULL,      -- pending | approved | rejected | cancelled | sent
    approved_by  TEXT,
    cooling_until REAL,              -- is time ke baad hi sign hoga
    tx_id        TEXT
);
"""
COOLING_SECONDS = 30


class PaymentError(Exception):
    pass


class PaymentService:
    def __init__(self, db_path, signer, clock=time.time):
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.executescript(SCHEMA)
        self.signer = signer        # signer(payment_dict) -> tx_id. Testnet wallet yahin jaata hai.
        self.clock = clock          # time ka source, test mein fake kar sakte hain

    def _row(self, payment_id):
        cur = self.db.execute("SELECT * FROM payments WHERE payment_id=?", (payment_id,))
        row = cur.fetchone()
        if row is None:
            raise PaymentError("payment not found")
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))

    def _set(self, payment_id, **fields):
        cols = ", ".join(f"{k}=?" for k in fields)
        with self.db:
            self.db.execute(f"UPDATE payments SET {cols} WHERE payment_id=?",
                            (*fields.values(), payment_id))

    def prepare(self, run_id, recipient, amount_inr, site):
        # Agent yahi call karta hai. Sirf pending row banti hai.
        payment_id = uuid.uuid4().hex
        with self.db:
            self.db.execute(
                "INSERT INTO payments (payment_id, run_id, recipient, amount_inr, site, status) "
                "VALUES (?,?,?,?,?,'pending')",
                (payment_id, run_id, recipient, amount_inr, site),
            )
        return payment_id

    def get(self, payment_id):
        # Confirmation screen yahin se padhta hai, agent se nahi.
        return self._row(payment_id)

    def approve(self, payment_id, approved_by):
        p = self._row(payment_id)
        if p["status"] != "pending":
            raise PaymentError(f"cannot approve, status is {p['status']}")
        self._set(payment_id, status="approved", approved_by=approved_by,
                  cooling_until=self.clock() + COOLING_SECONDS)

    def reject(self, payment_id):
        p = self._row(payment_id)
        if p["status"] not in ("pending", "approved"):
            raise PaymentError(f"cannot reject, status is {p['status']}")
        self._set(payment_id, status="rejected")

    def cancel(self, payment_id):
        # Cooling ke dauran user ruk sakta hai
        p = self._row(payment_id)
        if p["status"] != "approved" or self.clock() >= p["cooling_until"]:
            raise PaymentError("cannot cancel now")
        self._set(payment_id, status="cancelled")

    def send(self, payment_id):
        # Cooling khatam hone ke baad hi. Amount database se aata hai, kisi input se nahi.
        p = self._row(payment_id)
        if p["status"] != "approved":
            raise PaymentError(f"not approved, status is {p['status']}")
        if self.clock() < p["cooling_until"]:
            raise PaymentError("cooling period not over")
        tx_id = self.signer(p)
        self._set(payment_id, status="sent", tx_id=tx_id)
        return tx_id
