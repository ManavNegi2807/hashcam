# canon.py: data ko hamesha ek hi fixed text/bytes mein badalne ke functions.
import json
import hashlib


def canonical(obj) -> bytes:
    # dict -> text -> bytes. Keys sorted, spaces nahi, UTF-8.
    return json.dumps(
        obj,
        sort_keys=True,          # keys alphabet order mein
        separators=(",", ":"),   # comma aur colon ke baad space nahi
        ensure_ascii=False,      # Hindi/emoji jaise hain waise rahein
        allow_nan=False,         # NaN/Infinity allowed nahi (JSON mein valid nahi)
    ).encode("utf-8")            # text ko bytes mein (hash bytes pe hi nikalta hai)


def sha256_hex(data: bytes) -> str:
    # bytes ka 64-character fingerprint (hex text)
    return hashlib.sha256(data).hexdigest()


def entry_hash(body: dict) -> str:
    # entry ke body ka hash. Body mein hash aur sig nahi hote.
    return sha256_hex(canonical(body))
