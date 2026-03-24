from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import yaml

# Ordered: specific high-risk tokens before looser patterns (overlap safety).
_BuiltinFn = Callable[[str, bool], str]


def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    alt = False
    for ch in reversed(digits):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _redact_credit_cards(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    # Sequences of 13–19 digits allowing single spaces or hyphens between digit groups.
    pattern = re.compile(r"\b(?:\d[ -]*?){12,18}\d\b")

    def repl(m: re.Match[str]) -> str:
        raw = m.group(0)
        d = re.sub(r"\D", "", raw)
        if 13 <= len(d) <= 19 and _luhn_valid(d):
            return "[CARD]"
        return raw

    return pattern.sub(repl, text)


def _redact_ssn(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    dashed = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    spaced = re.compile(r"\b\d{3}\s+\d{2}\s+\d{4}\b")
    out = dashed.sub("[SSN]", text)
    return spaced.sub("[SSN]", out)


def _redact_ein(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    return re.compile(r"\b\d{2}-\d{7}\b").sub("[EIN]", text)


def _redact_email(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    rx = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        re.IGNORECASE,
    )
    return rx.sub("[EMAIL]", text)


def _redact_phone_us(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    rx = re.compile(
        r"(?<!\d)(?:\+1\s*)?(?:\(\s*\d{3}\s*\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
    )
    return rx.sub("[PHONE]", text)


def _valid_date_iso(s: str) -> bool:
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _redact_date_iso(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    rx = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")

    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        return "[DATE]" if _valid_date_iso(s) else s

    return rx.sub(repl, text)


def _valid_date_us(s: str) -> bool:
    for fmt in ("%m/%d/%Y", "%m/%d/%y", "%d/%m/%Y", "%d/%m/%y"):
        try:
            datetime.strptime(s, fmt)
            return True
        except ValueError:
            continue
    return False


def _redact_date_us_slash(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    rx = re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b")

    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        return "[DATE]" if _valid_date_us(s) else s

    return rx.sub(repl, text)


def _redact_ipv4(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    n = len(text)
    out: list[str] = []
    last = 0
    i = 0
    while i < n:
        if not text[i].isdigit():
            i += 1
            continue
        matched_len = 0
        for length in range(15, 6, -1):
            if i + length > n:
                continue
            cand = text[i : i + length]
            if not all(c.isdigit() or c == "." for c in cand):
                continue
            if cand.count(".") != 3:
                continue
            try:
                ipaddress.IPv4Address(cand)
                matched_len = length
                break
            except ValueError:
                continue
        if matched_len:
            out.append(text[last:i])
            out.append("[IPV4]")
            last = i + matched_len
            i = last
        else:
            i += 1
    out.append(text[last:])
    return "".join(out)


def _redact_ipv6(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    n = len(text)
    out: list[str] = []
    last = 0
    i = 0
    while i < n:
        c = text[i]
        if c not in "0123456789abcdefABCDEF:":
            i += 1
            continue
        matched_len = 0
        for length in range(39, 3, -1):
            if i + length > n:
                continue
            cand = text[i : i + length]
            if cand.count(":") < 2:
                continue
            if not all(ch in "0123456789abcdefABCDEF:." for ch in cand):
                continue
            try:
                ipaddress.IPv6Address(cand)
                matched_len = length
                break
            except ValueError:
                continue
        if matched_len:
            out.append(text[last:i])
            out.append("[IPV6]")
            last = i + matched_len
            i = last
        else:
            i += 1
    out.append(text[last:])
    return "".join(out)


def _redact_metrc_like(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    rx = re.compile(r"\b[A-Z0-9]{20,28}\b")
    return rx.sub("[METRC_ID]", text)


_BUILTIN_PIPELINE: list[tuple[str, _BuiltinFn]] = [
    ("credit_card", _redact_credit_cards),
    ("ssn", _redact_ssn),
    ("ein", _redact_ein),
    ("email", _redact_email),
    ("phone_us", _redact_phone_us),
    ("date_iso", _redact_date_iso),
    ("date_us_slash", _redact_date_us_slash),
    ("ipv6", _redact_ipv6),
    ("ipv4", _redact_ipv4),
    ("metrc_like_ids", _redact_metrc_like),
]


def load_config(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    p = Path(path)
    if not p.is_file():
        return {}
    with p.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _sorted_phrases(items: list[str] | None) -> list[str]:
    if not items:
        return []
    unique = sorted({s.strip() for s in items if s and s.strip()})
    return sorted(unique, key=len, reverse=True)


def anonymize(text: str, config: dict[str, Any] | None = None) -> str:
    """Apply configured and built-in redactions to ``text``.

    Built-ins target common PHI/PII shapes (SSN, EIN, dates, cards with Luhn,
    emails, phones, IPs, METRC-like tokens). They do **not** remove arbitrary
    person names or free-form addresses without list configuration.
    """
    cfg = config or {}
    builtins = cfg.get("builtins") or {}
    out = text

    for name, fn in _BUILTIN_PIPELINE:
        enabled = builtins.get(name, True)
        out = fn(out, enabled)

    for phrase in _sorted_phrases(cfg.get("strains")):
        out = re.compile(re.escape(phrase), re.IGNORECASE).sub(
            "[STRAIN]", out
        )

    for phrase in _sorted_phrases(cfg.get("companies")):
        out = re.compile(re.escape(phrase), re.IGNORECASE).sub(
            "[COMPANY]", out
        )

    for phrase in _sorted_phrases(cfg.get("people")):
        out = re.compile(re.escape(phrase), re.IGNORECASE).sub(
            "[PERSON]", out
        )

    for entry in cfg.get("extra_patterns") or []:
        if not isinstance(entry, dict):
            continue
        pat = entry.get("pattern")
        repl = entry.get("replacement", "[REDACTED]")
        if not pat:
            continue
        out = re.compile(pat).sub(repl, out)

    return out
