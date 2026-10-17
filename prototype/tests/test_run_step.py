# test_run_step.py: action ke parameters log mein digest + masked roop mein jaate hain (Step 0).
import hashlib
import json

from agent.run_step import RunStep
from ledger.chain import Chain, new_key
from ledger.verify import verify


class FakeStore:
    def __init__(self):
        self.rows = []

    def append(self, run_id, entry):
        self.rows.append(entry)

    def save_shot(self, png):
        return ""


class AllowGuard:
    def check(self, url, action, params):
        return "allow", ""


class FakeFish:
    def run(self, url, action, params):
        return "ok", b""


def make():
    key = new_key()
    store = FakeStore()
    step = RunStep(Chain(key), store, "r1", AllowGuard(), FakeFish())
    return step, store, key


def test_params_are_logged_as_digest_plus_masked_values():
    step, store, _ = make()
    step("shop", "type", {"field": "card", "value": "4111 1111 1111 1111"})
    action = store.rows[0]["action"]
    assert "4111 1111 1111 1111" not in action
    assert "****1111" in action
    raw = json.dumps(
        {"field": "card", "value": "4111 1111 1111 1111"}, sort_keys=True, separators=(",", ":")
    )
    assert hashlib.sha256(raw.encode()).hexdigest() in action


def test_no_params_leaves_the_action_unchanged():
    step, store, _ = make()
    step("shop", "read")
    assert store.rows[0]["action"] == "read"


def test_chain_still_verifies_with_params_logged():
    step, store, key = make()
    step("shop", "type", {"value": "password: hunter2"})
    assert "hunter2" not in store.rows[0]["action"]
    assert (
        verify(store.rows, key.public_key()) == (True, "ok")
        or verify(store.rows, key.public_key())[0]
    )
