# mask.py: card, OTP aur password ko log mein jaane se pehle chhupata hai.
import re

CARD = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")           # 13 se 19 digits, beech mein space/dash allowed
OTP = re.compile(r"(?i)(otp\D{0,20})(\d{4,8})")           # "otp" ke baad 4-8 digits
PASSWORD = re.compile(r"(?i)(password|pass|pwd|cvv)(\s*[:=]\s*)(\S+)")   # keyword : value


def _card(m):
    # card ke sirf digits, last 4 rakho, baaki ****
    digits = re.sub(r"\D", "", m.group(0))
    return "****" + digits[-4:]


def mask(text: str) -> str:
    # Hash se pehle hi chalao, taaki card hash ke andar bhi na jaaye.
    text = CARD.sub(_card, text)                                    # card -> ****1111
    text = OTP.sub(lambda m: m.group(1) + "****", text)             # otp ki value -> ****
    text = PASSWORD.sub(lambda m: m.group(1) + m.group(2) + "****", text)  # password value -> ****
    return text
