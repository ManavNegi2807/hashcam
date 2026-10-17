# test_serve.py: launcher keys file se uthata hai aur kuch print nahi karta.
import contextlib
import io

from cryptography.hazmat.primitives import serialization as s
from fastapi.testclient import TestClient
from ledger.chain import new_key


def test_launcher_builds_from_files_and_prints_nothing(tmp_path, monkeypatch):
    k = new_key()
    (tmp_path / "sk").write_bytes(
        k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())
    )
    (tmp_path / "pk").write_bytes(
        k.public_key().public_bytes(s.Encoding.PEM, s.PublicFormat.SubjectPublicKeyInfo)
    )
    (tmp_path / "rt").write_text("read-secret-token\n")
    (tmp_path / "pt").write_text("pay-secret-token\n")
    for name, val in {
        "SIGNING_KEY_PATH": "sk",
        "PUBLIC_KEY_PATH": "pk",
        "READ_TOKEN_PATH": "rt",
        "PAY_TOKEN_PATH": "pt",
    }.items():
        monkeypatch.setenv(name, str(tmp_path / val))
    monkeypatch.setenv("DB_PATH", str(tmp_path / "log.db"))
    monkeypatch.setenv("SHOTS_DIR", str(tmp_path / "shots"))
    monkeypatch.setenv("PAYMENT_DB_PATH", str(tmp_path / "pay.db"))
    from ledger.serve import build

    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        app = build()
    assert out.getvalue() == ""
    c = TestClient(app)
    assert c.get("/health").json() == {"ok": True}
    assert c.post("/runs").status_code == 401
    assert c.post("/runs", headers={"Authorization": "Bearer read-secret-token"}).status_code == 200
