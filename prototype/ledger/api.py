# api.py: ledger ki HTTP API. Har endpoint par token check hota hai (log access control, SR-06).
import hmac
import threading
import uuid

from fastapi import FastAPI, Header, HTTPException

from .chain import Chain
from .verify import verify


def create_app(store, payments, signing_key, public_key, read_token, pay_token):
    app = FastAPI()
    runs = {}   # run_id -> Chain (memory mein; restart par reset)
    lock = threading.Lock()   # ek time par ek hi DB call (SQLite safety)

    def need(token_expected, authorization):
        # "Bearer <token>" se token nikaalo, aur safe compare karo
        given = (authorization or "").removeprefix("Bearer ")
        if not hmac.compare_digest(given, token_expected):
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health():
        return {"ok": True}      # koi data nahi, sirf zinda hai ya nahi

    @app.post("/runs")
    def create_run(authorization: str = Header(None)):
        need(read_token, authorization)
        run_id = uuid.uuid4().hex
        runs[run_id] = Chain(signing_key)
        return {"run_id": run_id}

    @app.get("/runs/{run_id}/entries")
    def entries(run_id: str, authorization: str = Header(None)):
        need(read_token, authorization)
        with lock:
            return store.load(run_id)

    @app.get("/runs/{run_id}/verify")
    def check(run_id: str, authorization: str = Header(None)):
        need(read_token, authorization)
        with lock:
            ok, msg = verify(store.load(run_id), public_key)
        return {"ok": ok, "message": msg}

    @app.post("/payments/{payment_id}/approve")
    def approve(payment_id: str, approved_by: str, authorization: str = Header(None)):
        need(pay_token, authorization)          # sirf payment service ka token
        with lock:
            payments.approve(payment_id, approved_by)
        return {"payment_id": payment_id, "status": "approved"}

    return app
