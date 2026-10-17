# api.py: demo UI ka server. Log dikhata hai, verify karta hai, aur tamper demo sirf ek COPY par karta hai.
# Is process ke paas sirf PUBLIC key hai. Signing key kabhi nahi.
import json
import os
from copy import deepcopy
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from ledger.anchor import check_anchor
from ledger.store import Store
from ledger.verify import verify

INDEX = Path(__file__).parent / "index.html"


def _verdict(run_id, rows, public_key, anchor):
    ok, msg = verify(rows, public_key)                      # chain, hash, signature
    if ok and anchor and anchor["run_id"] == run_id:
        ok, msg = check_anchor(rows, anchor)                # truncation ke liye anchor
    return {"ok": ok, "message": msg}


def create_ui(store, public_key, anchor=None):
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def index():
        return INDEX.read_text(encoding="utf-8")

    @app.get("/api/runs/{run_id}/entries")
    def entries(run_id: str):
        return store.load(run_id)

    @app.get("/api/runs/{run_id}/verify")
    def check(run_id: str):
        return _verdict(run_id, store.load(run_id), public_key, anchor)

    @app.post("/api/runs/{run_id}/tamper/{kind}")
    def tamper(run_id: str, kind: str):
        rows = deepcopy(store.load(run_id))                 # asli DB ko hath nahi lagta
        if not rows:
            raise HTTPException(status_code=404, detail="run not found")
        mid = len(rows) // 2
        if kind == "edit":
            rows[mid]["result"] = "Rs 1 (tampered)"
        elif kind == "delete":
            del rows[mid]
        elif kind == "truncate":
            rows = rows[:-2]
        else:
            raise HTTPException(status_code=400, detail="unknown kind")
        return _verdict(run_id, rows, public_key, anchor)

    return app


def build():
    # uvicorn ui.api:build --factory   (env variables se setup)
    store = Store(os.environ["DB_PATH"], os.environ["SHOTS_DIR"])
    with open(os.environ["PUBLIC_KEY_PATH"], "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    anchor = None
    anchor_path = os.environ.get("ANCHOR_PATH")
    if anchor_path and Path(anchor_path).exists():
        anchor = json.loads(Path(anchor_path).read_text(encoding="utf-8"))
    return create_ui(store, public_key, anchor)
