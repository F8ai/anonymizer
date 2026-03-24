"""LLM-assisted review of anonymizer output (assistive only — not legal Expert Determination)."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

REVIEW_SYSTEM = """You are a technical privacy review assistant helping engineers evaluate rule-based text anonymization.

CRITICAL LIMITATIONS (state these briefly in your JSON "notes" if relevant):
- You are NOT a lawyer. This is NOT a HIPAA Expert Determination, legal advice, or formal compliance sign-off.
- You only see the text provided; you cannot know the full data environment or linkage attacks available to a motivated party.

Your job: critically review the REDACTED text (and optional diff vs ORIGINAL) for residual identifiers and re-identification risk.

Consider:
1) Direct identifiers: names, geographic detail below state, dates finer than year, phone/fax/email, URLs, IP-like strings, account/MRN/credential-like codes, vehicle/device serials, biometric or full-face references.
2) Cannabis / METRC-style context: package/manifest style tags, license numbers, facility combinations that could be unique.
3) Narrative re-identification: rare events, timing + role + location, small-N descriptions.
4) HIPAA Safe Harbor (45 CFR 164.514(b)(2)): flag categories that still appear or seem inferable from context.
5) Placeholder hygiene: suspicious literals, inconsistent tokens, or text that looks like a missed pattern.

Respond with VALID JSON ONLY (no markdown code fences), exactly this shape:
{"summary":"string","residual_risk":"low|medium|high","safe_harbor_concerns":["string"],"metrc_concerns":["string"],"suggested_config_changes":["string"],"notes":"string"}
"""


def _read_file_or_stdin(path: Path | None) -> str:
    if path is not None:
        return path.read_text(encoding="utf-8")
    return sys.stdin.read()


def _config_summary(config_path: Path | None) -> str | None:
    if config_path is None or not config_path.is_file():
        return None
    data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    lines = ["YAML config summary (high level):"]
    for key in ("strains", "companies", "people", "extra_patterns", "builtins"):
        if key not in data:
            continue
        val = data[key]
        if key == "builtins" and isinstance(val, dict):
            disabled = [k for k, v in val.items() if v is False]
            if disabled:
                lines.append(f"  builtins disabled: {', '.join(disabled)}")
            continue
        if isinstance(val, list):
            lines.append(f"  {key}: {len(val)} entries")
        elif isinstance(val, dict):
            lines.append(f"  {key}: {len(val)} keys")
        else:
            lines.append(f"  {key}: present")
    return "\n".join(lines) if len(lines) > 1 else None


def _mapping_meta(mapping_path: Path | None) -> tuple[int | None, list[str]]:
    """Return (count, kind prefixes from placeholder keys) without sending values."""
    if mapping_path is None or not mapping_path.is_file():
        return None, []
    raw = json.loads(mapping_path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return None, []
    kinds: set[str] = set()
    for k in raw:
        if isinstance(k, str) and k.startswith("[") and "_" in k:
            inner = k.strip("[]")
            kind = inner.rsplit("_", 1)[0]
            kinds.add(kind)
    return len(raw), sorted(kinds)


def build_user_message(
    *,
    redacted: str,
    original: str | None,
    mapping_count: int | None,
    mapping_kinds: list[str],
    config_summary: str | None,
) -> str:
    parts = [
        "## REDACTED TEXT (as would be sent to a third-party LLM)\n",
        redacted.strip() if redacted else "(empty)",
        "\n",
    ]
    if original is not None:
        parts += [
            "## ORIGINAL TEXT (for diff — treat as sensitive; do not reproduce unnecessarily)\n",
            original.strip() if original else "(empty)",
            "\n",
        ]
    if mapping_count is not None:
        parts.append(
            f"## Mapping metadata only: {mapping_count} placeholders; kinds: {', '.join(mapping_kinds) or 'unknown'}\n"
            "(Values are NOT included to reduce exposure in this review channel.)\n\n"
        )
    if config_summary:
        parts.append(f"## Config\n{config_summary}\n\n")
    parts.append("Produce the JSON review object now.")
    return "".join(parts)


def call_openrouter(
    messages: list[dict[str, str]],
    *,
    model: str,
    api_key: str,
    site_url: str | None = None,
    app_title: str | None = None,
) -> str:
    url = os.environ.get("OPENROUTER_API_URL", "https://openrouter.ai/api/v1/chat/completions")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if site_url:
        headers["HTTP-Referer"] = site_url
    if app_title:
        headers["X-Title"] = app_title
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenRouter HTTP {e.code}: {err_body}") from e
    try:
        return str(payload["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as e:
        raise RuntimeError(f"Unexpected OpenRouter response: {payload!r}") from e


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run an LLM 'expert review' pass over anonymized text. "
            "Assistive only — not HIPAA Expert Determination or legal advice."
        ),
        epilog=(
            "If you use --original with an API call, the original text is sent to OpenRouter — "
            "only do that with data you are allowed to share with that provider."
        ),
    )
    parser.add_argument(
        "--redacted",
        type=Path,
        help="File with redacted text (default: stdin)",
    )
    parser.add_argument(
        "--original",
        type=Path,
        help="Optional original text for comparative review (sensitive)",
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        help="Optional mapping JSON — only placeholder kinds/count are summarized, not values",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        help="Optional anonymizer YAML config for context",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("ANONYMIZER_REVIEW_MODEL", "openai/gpt-4o-mini"),
        help="OpenRouter model id (default: openai/gpt-4o-mini or ANONYMIZER_REVIEW_MODEL)",
    )
    parser.add_argument(
        "--print-prompt",
        action="store_true",
        help="Print messages JSON to stdout and exit (no API call)",
    )
    args = parser.parse_args()

    redacted = _read_file_or_stdin(args.redacted)
    original = args.original.read_text(encoding="utf-8") if args.original else None
    mc, mkinds = _mapping_meta(args.mapping)
    csum = _config_summary(args.config)
    user_msg = build_user_message(
        redacted=redacted,
        original=original,
        mapping_count=mc,
        mapping_kinds=mkinds,
        config_summary=csum,
    )
    messages = [
        {"role": "system", "content": REVIEW_SYSTEM},
        {"role": "user", "content": user_msg},
    ]

    if args.print_prompt:
        print(json.dumps(messages, indent=2, ensure_ascii=False))
        return

    key = os.environ.get("OPENROUTER_API_KEY", "")
    if not key:
        print(
            "OPENROUTER_API_KEY is not set. Use --print-prompt to export the review prompt, "
            "or set the key to call OpenRouter.",
            file=sys.stderr,
        )
        sys.exit(2)

    out = call_openrouter(
        messages,
        model=args.model,
        api_key=key,
        site_url=os.environ.get("OPENROUTER_SITE_URL"),
        app_title=os.environ.get("OPENROUTER_APP_TITLE", "anonymizer-review"),
    )
    sys.stdout.write(out)
    if not out.endswith("\n"):
        sys.stdout.write("\n")


if __name__ == "__main__":  # pragma: no cover
    main()
