# Agent Black Box

**Status (Step 0 of the v10 build):** the prototype is `TESTED` by its own pytest suite
(25 tests: the original 21, 3 for parameter logging, 1 for the launcher).
The Docker files and `docker-compose.yml` are `IMPLEMENTED` but **never run**: no Docker
daemon was available, so `docker build` and the secrets-not-in-image check are `UNVERIFIED`.
The prototype stays a demo; the v10 system lives outside this folder (`D-09`).

AI agent web par kaam karta hai. Har step ek hash chain mein signed record hota hai.
Koi bhi log badle, hata de, ya kaata ho, verifier red dikhata hai.
Payment agent nahi karta. Insaan confirmation screen par sign karta hai (testnet).

**Honest:** ye tamper-evident hai, hack-proof nahi.

## Run karna

1. Signing key banao (sirf ledger ke paas rehni chahiye):
   ```
   python -c "from ledger.chain import new_key; from cryptography.hazmat.primitives import serialization as s; k=new_key(); open('secrets/signing_key.pem','wb').write(k.private_bytes(s.Encoding.PEM,s.PrivateFormat.PKCS8,s.NoEncryption())); open('secrets/public_key.pem','wb').write(k.public_key().public_bytes(s.Encoding.PEM,s.PublicFormat.SubjectPublicKeyInfo))"
   ```
2. Docker se chalao:
   ```
   docker compose up --build
   ```
3. Browser mein `http://localhost:8000` kholo. Run ID daalo, Load, Verify, aur Tamper buttons dabao.

Local bina Docker ke:
```
pip install -r requirements.txt
DB_PATH=log.db SHOTS_DIR=shots PUBLIC_KEY_PATH=secrets/public_key.pem uvicorn ui.api:build --factory
```

## Files

| Folder | Kaam |
|---|---|
| `ledger/` | Hash chain, signature, verifier, store, masking, anchor, API |
| `agent/` | `run_step` (ek hi darwaza), LangGraph loop |
| `guard/` | Allowlist, recipient, limit, approval |
| `payment/` | Prepare, approve, 30 sec cooling, cancel, send |
| `ui/` | Demo page aur server (sirf public key) |
| `tests/` | pytest |

## Tests

```
pytest -q
```

## Abhi nahi hai (future work)

- TinyFish ka asli client (abhi fake use hua hai)
- Agent container aur internal network ka asli test
- Asli user login (approved_by sirf naam hai)
- Trusted timestamp, multi-signature, KMS/HSM
- Encryption at rest, dependency scan
