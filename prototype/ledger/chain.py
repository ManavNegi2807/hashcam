# chain.py: entries ko ek-ek karke jodta hai, har entry ko pichli se link karta hai aur sign karta hai.
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .canon import entry_hash
from .mask import mask

GENESIS = "0" * 64   # pehli entry ka "pichla hash" (chain ki shuruaat)


def new_key():
    # naya Ed25519 private key banata hai (test ke liye). Asli project mein key file/secret se aayegi.
    return Ed25519PrivateKey.generate()


class Chain:
    def __init__(self, private_key):
        self.key = private_key   # sign karne ki key
        self.entries = []        # saari entries yahin jama hongi

    def append(self, url, action, result, shot=""):
        # pichli entry ka hash lo, pehli ho to GENESIS
        prev = self.entries[-1]["hash"] if self.entries else GENESIS

        body = {
            "n": len(self.entries),          # step number, 0 se shuru
            "time": int(time.time() * 1000), # milliseconds, integer (float se text alag banta hai)
            "url": url,
            "action": action,
            "result": mask(result),          # hash se pehle masking
            "shot": shot,                    # screenshot ka hash, na ho to khaali
            "prev": prev,                    # chain ka link
        }
        h = entry_hash(body)                       # body ka fingerprint
        sig = self.key.sign(h.encode()).hex()      # fingerprint par signature, text ke roop mein
        entry = {**body, "hash": h, "sig": sig}    # body + hash + sig ek entry mein
        self.entries.append(entry)
        return entry
