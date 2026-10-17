# serve.py: ledger API ka launcher. Keys aur tokens mounted file se aate hain, env se sirf path.
# Kuch bhi print nahi hota: na key, na token.
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .api import create_app
from .store import Store


def _read(path_env):
    return Path(os.environ[path_env]).read_bytes()


def _refuse_signer(payment):
    # asli testnet wallet abhi nahi hai. Bhejna refuse hota hai, chup-chaap fake tx nahi banta.
    raise RuntimeError("no testnet wallet is configured")


def build():
    # uvicorn ledger.serve:build --factory
    from payment.payment import PaymentService

    signing_key = serialization.load_pem_private_key(_read("SIGNING_KEY_PATH"), password=None)
    public_key = serialization.load_pem_public_key(_read("PUBLIC_KEY_PATH"))
    read_token = _read("READ_TOKEN_PATH").decode().strip()
    pay_token = _read("PAY_TOKEN_PATH").decode().strip()
    store = Store(os.environ["DB_PATH"], os.environ["SHOTS_DIR"])
    payments = PaymentService(os.environ["PAYMENT_DB_PATH"], _refuse_signer)
    return create_app(store, payments, signing_key, public_key, read_token, pay_token)
