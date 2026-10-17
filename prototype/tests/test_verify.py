import copy
from ledger.chain import Chain, new_key
from ledger.verify import verify


def setup():
    key = new_key()
    c = Chain(key)
    for i in range(5):
        c.append("shop", "read", f"Rs {1000 + i}")
    return c.entries, key.public_key()


def test_untouched_ok():
    entries, pub = setup()
    assert verify(entries, pub) == (True, "OK (5 steps)")


def test_edit_detected():
    entries, pub = setup()
    e = copy.deepcopy(entries); e[2]["result"] = "Rs 1"
    assert verify(e, pub) == (False, "TAMPERED at step 2")


def test_delete_detected():
    entries, pub = setup()
    e = copy.deepcopy(entries); del e[2]
    assert verify(e, pub) == (False, "TAMPERED at step 2")


def test_reorder_detected():
    entries, pub = setup()
    e = copy.deepcopy(entries); e[1], e[2] = e[2], e[1]
    assert verify(e, pub)[0] is False


def test_bad_signature_detected():
    entries, pub = setup()
    e = copy.deepcopy(entries); e[3]["sig"] = "00" * 64
    assert verify(e, pub) == (False, "BAD SIGNATURE at step 3")


def test_wrong_key_detected():
    entries, _ = setup()
    other = new_key().public_key()
    assert verify(entries, other) == (False, "BAD SIGNATURE at step 0")
