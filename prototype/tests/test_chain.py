from ledger.chain import Chain, new_key, GENESIS


def make_chain(n=3):
    c = Chain(new_key())
    for i in range(n):
        c.append("shop", "read", f"Rs {1000 + i}")
    return c


def test_first_prev_is_genesis():
    assert make_chain().entries[0]["prev"] == GENESIS


def test_prev_links_to_previous_hash():
    e = make_chain().entries
    assert e[1]["prev"] == e[0]["hash"]
    assert e[2]["prev"] == e[1]["hash"]


def test_numbers_are_sequential():
    assert [x["n"] for x in make_chain(4).entries] == [0, 1, 2, 3]
