from ledger.canon import canonical, entry_hash


def test_key_order_does_not_matter():
    assert canonical({"a": 1, "b": 2}) == canonical({"b": 2, "a": 1})


def test_no_spaces():
    assert canonical({"a": 1}) == b'{"a":1}'


def test_hash_changes_on_edit():
    assert entry_hash({"n": 1, "result": "Rs 23999"}) != entry_hash({"n": 1, "result": "Rs 22999"})
