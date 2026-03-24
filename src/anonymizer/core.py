from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Literal, Mapping, overload

import yaml

# Roles whose message bodies are redacted when sending to third-party LLMs (see anonymize_messages).
DEFAULT_ANONYMIZE_MESSAGE_ROLES: frozenset[str] = frozenset({"user", "tool"})

# Ordered: specific high-risk tokens before looser patterns (overlap safety).
_BuiltinFn = Callable[[str, bool, "RedactionState"], str]


@dataclass
class RedactionState:
    """Tracks placeholder → original value for round-trip unredaction."""

    mapping: dict[str, str] = field(default_factory=dict)
    _counts: dict[str, int] = field(default_factory=dict)

    def token(self, kind: str, original: str) -> str:
        """Return a unique placeholder such as ``[EMAIL_1]`` and record mapping."""
        n = self._counts.get(kind, 0) + 1
        self._counts[kind] = n
        ph = f"[{kind}_{n}]"
        self.mapping[ph] = original
        return ph


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


def _redact_credit_cards(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    pattern = re.compile(r"\b(?:\d[ -]*?){12,18}\d\b")

    def repl(m: re.Match[str]) -> str:
        raw = m.group(0)
        d = re.sub(r"\D", "", raw)
        if 13 <= len(d) <= 19 and _luhn_valid(d):
            return st.token("CARD", raw)
        return raw

    return pattern.sub(repl, text)


def _redact_ssn(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    dashed = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    spaced = re.compile(r"\b\d{3}\s+\d{2}\s+\d{4}\b")

    def sub_d(m: re.Match[str]) -> str:
        return st.token("SSN", m.group(0))

    def sub_s(m: re.Match[str]) -> str:
        return st.token("SSN", m.group(0))

    out = dashed.sub(sub_d, text)
    return spaced.sub(sub_s, out)


def _redact_ein(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    rx = re.compile(r"\b\d{2}-\d{7}\b")

    def repl(m: re.Match[str]) -> str:
        return st.token("EIN", m.group(0))

    return rx.sub(repl, text)


def _redact_email(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    rx = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        re.IGNORECASE,
    )

    def repl(m: re.Match[str]) -> str:
        return st.token("EMAIL", m.group(0))

    return rx.sub(repl, text)


def _redact_phone_us(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    rx = re.compile(
        r"(?<!\d)(?:\+1\s*)?(?:\(\s*\d{3}\s*\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
    )

    def repl(m: re.Match[str]) -> str:
        return st.token("PHONE", m.group(0))

    return rx.sub(repl, text)


def _valid_date_iso(s: str) -> bool:
    try:
        datetime.strptime(s, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def _redact_date_iso(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    rx = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")

    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        return st.token("DATE", s) if _valid_date_iso(s) else s

    return rx.sub(repl, text)


def _valid_date_us(s: str) -> bool:
    for fmt in ("%m/%d/%Y", "%m/%d/%y", "%d/%m/%Y", "%d/%m/%y"):
        try:
            datetime.strptime(s, fmt)
            return True
        except ValueError:
            continue
    return False


def _redact_date_us_slash(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    rx = re.compile(r"\b\d{1,2}/\d{1,2}/\d{2,4}\b")

    def repl(m: re.Match[str]) -> str:
        s = m.group(0)
        return st.token("DATE", s) if _valid_date_us(s) else s

    return rx.sub(repl, text)


def _redact_ipv4(text: str, enabled: bool, st: RedactionState) -> str:
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
            out.append(st.token("IPV4", text[i : i + matched_len]))
            last = i + matched_len
            i = last
        else:
            i += 1
    out.append(text[last:])
    return "".join(out)


def _redact_ipv6(text: str, enabled: bool, st: RedactionState) -> str:
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
            out.append(st.token("IPV6", text[i : i + matched_len]))
            last = i + matched_len
            i = last
        else:
            i += 1
    out.append(text[last:])
    return "".join(out)


def _redact_metrc_like(text: str, enabled: bool, st: RedactionState) -> str:
    if not enabled:
        return text
    rx = re.compile(r"\b[A-Z0-9]{20,28}\b")

    def repl(m: re.Match[str]) -> str:
        return st.token("METRC", m.group(0))

    return rx.sub(repl, text)


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


def _redact_plain_text(text: str, cfg: dict[str, Any], st: RedactionState) -> str:
    """Apply full redaction pipeline to a single string, mutating ``st``."""
    builtins = cfg.get("builtins") or {}
    out = text

    for name, fn in _BUILTIN_PIPELINE:
        enabled = builtins.get(name, True)
        out = fn(out, enabled, st)

    for phrase in _sorted_phrases(cfg.get("strains")):
        pat = re.compile(re.escape(phrase), re.IGNORECASE)

        def sub_strain(m: re.Match[str]) -> str:
            return st.token("STRAIN", m.group(0))

        out = pat.sub(sub_strain, out)

    for phrase in _sorted_phrases(cfg.get("companies")):
        pat = re.compile(re.escape(phrase), re.IGNORECASE)

        def sub_company(m: re.Match[str]) -> str:
            return st.token("COMPANY", m.group(0))

        out = pat.sub(sub_company, out)

    for phrase in _sorted_phrases(cfg.get("people")):
        pat = re.compile(re.escape(phrase), re.IGNORECASE)

        def sub_person(m: re.Match[str]) -> str:
            return st.token("PERSON", m.group(0))

        out = pat.sub(sub_person, out)

    for entry in cfg.get("extra_patterns") or []:
        if not isinstance(entry, dict):
            continue
        pat_s = entry.get("pattern")
        if not pat_s:
            continue
        rx = re.compile(pat_s)

        def sub_extra(m: re.Match[str]) -> str:
            return st.token("EXTRA", m.group(0))

        out = rx.sub(sub_extra, out)

    return out


def _redact_multimodal_parts(parts: list[Any], cfg: dict[str, Any], st: RedactionState) -> list[Any]:
    out: list[Any] = []
    for p in parts:
        if isinstance(p, dict) and p.get("type") == "text" and isinstance(p.get("text"), str):
            q = dict(p)
            q["text"] = _redact_plain_text(p["text"], cfg, st)
            out.append(q)
        else:
            out.append(p)
    return out


def anonymize_messages(
    messages: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
    *,
    roles: frozenset[str] = DEFAULT_ANONYMIZE_MESSAGE_ROLES,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Redact string (or multimodal text) content for each message whose role is in ``roles``.

    Uses one shared :class:`RedactionState` so placeholders are unique across the transcript.
    """
    cfg = config or {}
    st = RedactionState()
    out: list[dict[str, Any]] = []
    for m in messages:
        if not isinstance(m, dict):
            out.append(m)
            continue
        m2 = dict(m)
        role = m2.get("role")
        if role not in roles:
            out.append(m2)
            continue
        content = m2.get("content")
        if isinstance(content, str):
            m2["content"] = _redact_plain_text(content, cfg, st)
        elif isinstance(content, list):
            m2["content"] = _redact_multimodal_parts(content, cfg, st)
        out.append(m2)
    return out, dict(st.mapping)


def unredact(text: str, mapping: Mapping[str, str]) -> str:
    """Replace placeholders in ``text`` using ``mapping`` (placeholder → original).

    Longest placeholders are expanded first so tokens like ``[EMAIL_10]`` are not
    confused with ``[EMAIL_1]``.
    """
    out = text
    for token in sorted(mapping.keys(), key=len, reverse=True):
        out = out.replace(token, mapping[token])
    return out


@overload
def anonymize(
    text: str,
    config: dict[str, Any] | None = None,
    *,
    return_mapping: Literal[False] = False,
) -> str: ...


@overload
def anonymize(
    text: str,
    config: dict[str, Any] | None = None,
    *,
    return_mapping: Literal[True],
) -> tuple[str, dict[str, str]]: ...


def anonymize(
    text: str,
    config: dict[str, Any] | None = None,
    *,
    return_mapping: bool = False,
) -> str | tuple[str, dict[str, str]]:
    """Apply configured and built-in redactions to ``text``.

    Each sensitive span is replaced by a unique placeholder ``[KIND_n]`` (e.g.
    ``[EMAIL_1]``, ``[SSN_2]``). Pass ``return_mapping=True`` to receive a dict
    suitable for :func:`unredact`.

    Built-ins target common PHI/PII shapes (SSN, EIN, dates, cards with Luhn,
    emails, phones, IPs, METRC-like tokens). They do **not** remove arbitrary
    person names or free-form addresses without list configuration.
    """
    cfg = config or {}
    st = RedactionState()
    out = _redact_plain_text(text, cfg, st)
    mapping = dict(st.mapping)
    if return_mapping:
        return out, mapping
    return out
