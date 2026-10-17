from guard.policy import Guard

def make():
    return Guard(allowed_sites=["shop.test"], recipients=["Test Shop"], limit_inr=500)

def test_allowed_site_read_is_allowed():
    assert make().check("shop.test", "read") == ("allow", "")

def test_site_not_on_allowlist_is_blocked():
    decision, _ = make().check("evil.test", "read")
    assert decision == "block"

def test_unknown_recipient_is_blocked():
    g = make()
    decision, _ = g.check("shop.test", "pay", {"recipient": "Someone", "amount_inr": 100})
    assert decision == "block"

def test_amount_above_limit_is_blocked():
    g = make()
    decision, _ = g.check("shop.test", "pay", {"recipient": "Test Shop", "amount_inr": 5000})
    assert decision == "block"

def test_payment_within_limit_needs_approval():
    g = make()
    decision, _ = g.check("shop.test", "pay", {"recipient": "Test Shop", "amount_inr": 499})
    assert decision == "need_approval"

def test_login_needs_approval():
    decision, _ = make().check("shop.test", "login")
    assert decision == "need_approval"
