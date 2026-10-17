# verify.py: poori chain check karta hai aur pehla toota step batata hai.
from cryptography.exceptions import InvalidSignature
from .canon import entry_hash

GENESIS = "0" * 64
BODY_KEYS = ("n", "time", "url", "action", "result", "shot", "prev")  # hash/sig ke bina wali fields


def verify(entries, public_key):
    # (True, "OK") ya (False, "TAMPERED at step n" / "BAD SIGNATURE at step n")
    prev = GENESIS   # pehli entry ka link zeros hona chahiye
    for i, e in enumerate(entries):           # i = step number (index), e = entry
        body = {k: e[k] for k in BODY_KEYS}   # entry se sirf body fields nikaalo

        # Check 1: number aur link. Entry hatai/badli gayi ya order toota?
        if e["n"] != i or e["prev"] != prev:
            return False, f"TAMPERED at step {i}"

        # Check 2: data. Body ka naya hash purane hash se match karta hai?
        if entry_hash(body) != e["hash"]:
            return False, f"TAMPERED at step {i}"

        # Check 3: signature. Asli public key se verify hoti hai?
        try:
            public_key.verify(bytes.fromhex(e["sig"]), e["hash"].encode())
        except (InvalidSignature, ValueError):   # galat signature ya kharab hex
            return False, f"BAD SIGNATURE at step {i}"

        prev = e["hash"]   # agli entry ke liye link
    return True, f"OK ({len(entries)} steps)"   # sab sahi
