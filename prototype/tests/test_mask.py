from ledger.mask import mask


def test_card_masked():
    assert "4111111111111111" not in mask("card 4111 1111 1111 1111 ok")
    assert "****1111" in mask("card 4111 1111 1111 1111 ok")


def test_password_masked():
    assert "hunter2" not in mask("password: hunter2")


def test_otp_masked():
    assert "123456" not in mask("your otp is 123456")
