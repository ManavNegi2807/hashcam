# run_step.py: agent ke liye web ka ek hi darwaza. Har action guard se check hota hai,
# TinyFish se chalta hai, aur record hota hai. Bina record ke koi step nahi.


import hashlib
import json
import re

from ledger.mask import mask

# in naam wale fields ki value kabhi log mein nahi jaati
SECRET_FIELD = re.compile(r"(?i)(key|token|secret|password|passwd|pwd|cvv|otp|private)")
PEM = re.compile(r"-----BEGIN[\s\S]*?(-----END[^-]*-----|$)")


class StepLimitReached(Exception):
    pass


class RunStep:
    def __init__(self, chain, store, run_id, guard, tinyfish, max_steps=20):
        self.chain = chain              # ledger chain (hash + sign)
        self.store = store              # SQLite + screenshots
        self.run_id = run_id            # is run ka id
        self.guard = guard              # check(url, action, params) -> (decision, reason)
        self.tinyfish = tinyfish        # run(url, action, params) -> (text, png_bytes)
        self.max_steps = max_steps      # M2: ek task mein maximum steps
        self.steps = 0

    @staticmethod
    def _describe(action, params):
        # params ka digest (asli bytes ka) + masked roop, taaki decision reconstruct ho sake
        if params is None:
            return action
        raw = json.dumps(params, sort_keys=True, separators=(",", ":"), default=str)
        digest = hashlib.sha256(raw.encode()).hexdigest()

        def clean(v, name=""):
            if isinstance(v, dict):
                return {k: clean(x, k) for k, x in v.items()}
            if isinstance(v, list):
                return [clean(x, name) for x in v]
            if SECRET_FIELD.search(name):
                return "****"
            return PEM.sub("****", mask(str(v)))

        shown = json.dumps(clean(params), sort_keys=True, separators=(",", ":"))
        return f"{action} params_sha256={digest} params={shown}"

    def _record(self, url, action, result, shot=""):
        entry = self.chain.append(url, action, result, shot=shot)   # result yahan masked hota hai
        self.store.append(self.run_id, entry)
        return entry

    def __call__(self, url, action, params=None):
        if self.steps >= self.max_steps:
            self._record(url, action, "STEP LIMIT reached")
            raise StepLimitReached(f"max {self.max_steps} steps")
        self.steps += 1

        decision, reason = self.guard.check(url, action, params)
        action = self._describe(action, params)
        if decision == "block":
            self._record(url, action, f"BLOCKED: {reason}")       # blocked bhi log mein jaata hai
            return None
        if decision == "need_approval":
            self._record(url, action, f"PENDING APPROVAL: {reason}")
            return None

        text, png = self.tinyfish.run(url, action, params)        # asli web kaam
        shot = self.store.save_shot(png) if png else ""           # screenshot hash
        self._record(url, action, text, shot=shot)
        return mask(text)                                         # agent ko bhi masked text (FR-44)
