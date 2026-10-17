# anchor.py: log ka latest hash bahar ki jagah par rakhta hai (GitHub gist).
# Iske baad koi aakhri entries kaatkar log dobara nahi likh sakta.
import json
import time


def make_anchor(run_id, entries, now=time.time):
    # Abhi ki sthiti: kitni entries hain, aur aakhri hash kya hai
    tip = entries[-1]["hash"] if entries else "0" * 64
    return {
        "run_id": run_id,
        "entry_count": len(entries),
        "tip_hash": tip,
        "time": int(now()),
    }


def publish(anchor, token, post, public=False):
    # post(url, headers, body) -> location. Asli HTTP call bahar se aata hai, test mein fake.
    body = {
        "description": f"Agent Black Box anchor {anchor['run_id']}",
        "public": public,
        "files": {"anchor.json": {"content": json.dumps(anchor, sort_keys=True)}},
    }
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    return post("https://api.github.com/gists", headers, body)


def check_anchor(entries, anchor):
    # Verifier yeh karta hai: anchor ke waqt jitni entries thi, woh abhi bhi hain aur hash match karta hai?
    n = anchor["entry_count"]
    if len(entries) < n:
        return False, "ANCHOR MISMATCH: log chhota hai (truncated)"
    if entries[n - 1]["hash"] != anchor["tip_hash"]:
        return False, "ANCHOR MISMATCH: hash match nahi karta"
    return True, "ANCHOR OK"
