from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_BUILTIN_PATTERNS: dict[str, tuple[re.Pattern[str], str]] = {
    "email": (
        re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            re.IGNORECASE,
        ),
        "[EMAIL]",
    ),
    "phone_us": (
        re.compile(
            r"(?<!\d)(?:\+1\s*)?(?:\(\s*\d{3}\s*\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
        ),
        "[PHONE]",
    ),
    # Common METRC package label style: long uppercase alphanumeric token
    "metrc_like_ids": (
        re.compile(r"\b[A-Z0-9]{20,28}\b"),
        "[METRC_ID]",
    ),
}


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
    """Apply configured and built-in redactions to ``text``."""
    cfg = config or {}
    out = text

    builtins = cfg.get("builtins") or {}
    for name, (rx, repl) in _BUILTIN_PATTERNS.items():
        if builtins.get(name, True):
            out = rx.sub(repl, out)

    for phrase in _sorted_phrases(cfg.get("strains")):
        out = re.compile(re.escape(phrase), re.IGNORECASE).sub(
            "[STRAIN]", out
        )

    for phrase in _sorted_phrases(cfg.get("companies")):
        out = re.compile(re.escape(phrase), re.IGNORECASE).sub(
            "[COMPANY]", out
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
