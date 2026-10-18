"""Privacy first: remove secrets and personal data before anything is stored or sent to a model."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict

_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_BEARER = re.compile(r"\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{12,}", re.I)
_APIKEY = re.compile(r"\b(sk_(?:live|test)_[A-Za-z0-9]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,})")
_SECRET = re.compile(r"""\b(pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth(?:orization)?)(["']?\s*[:=]\s*)("[^"\n]{3,}"|'[^'\n]{3,}'|[^\s,;&"']{3,})""", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PHONE = re.compile(r"(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b")
_PATH = re.compile(r"(/Users/|/home/|C:\\Users\\)([^/\\\s]+)")
_COOKIE = re.compile(r"^(\s*(?:Cookie|Set-Cookie):).*$", re.I | re.M)


@dataclass
class Redaction:
    text: str
    counts: Dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def redact(text: str, strict: bool = False) -> Redaction:
    counts: Dict[str, int] = {}

    def bump(k: str) -> None:
        counts[k] = counts.get(k, 0) + 1

    t = str(text or "")
    t = _JWT.sub(lambda m: (bump("jwt"), "[JWT]")[1], t)
    t = _BEARER.sub(lambda m: (bump("token"), m.group(1) + " [TOKEN]")[1], t)
    t = _APIKEY.sub(lambda m: (bump("apikey"), "[API_KEY]")[1], t)

    def secret(m: re.Match) -> str:
        v = m.group(3)
        if v.startswith("[") or re.fullmatch(r"(?i)bearer|basic", v) or re.fullmatch(r"\[?(REDACTED|TOKEN|JWT|API_KEY)\]?", v):
            return m.group(0)
        bump("secret")
        return m.group(1) + m.group(2) + "[REDACTED]"

    t = _SECRET.sub(secret, t)
    t = _EMAIL.sub(lambda m: (bump("email"), "[EMAIL]")[1], t)

    def card(m: re.Match) -> str:
        d = re.sub(r"\D", "", m.group(0))
        if 13 <= len(d) <= 19 and luhn(d):
            bump("card")
            return "[CARD]"
        return m.group(0)

    t = _CARD.sub(card, t)
    if strict:
        def ip(m: re.Match) -> str:
            if all(int(o) <= 255 for o in m.group(0).split(".")):
                bump("ip")
                return "[IP]"
            return m.group(0)

        t = _IP.sub(ip, t)
        t = _PHONE.sub(lambda m: (bump("phone"), "[PHONE]")[1], t)
        t = _PATH.sub(lambda m: (bump("path"), m.group(1) + "[USER]")[1], t)
        t = _COOKIE.sub(lambda m: (bump("cookie"), m.group(1) + " [REDACTED]")[1], t)
    return Redaction(t, counts)
