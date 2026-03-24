"""Tests for review prompt construction (review module omitted from coverage)."""

from __future__ import annotations

import json
from pathlib import Path

from anonymizer.review import (
    REVIEW_SYSTEM,
    _config_summary,
    _mapping_meta,
    build_user_message,
)


def test_review_system_mentions_not_legal() -> None:
    assert "NOT" in REVIEW_SYSTEM
    assert "Expert Determination" in REVIEW_SYSTEM


def test_build_user_message_minimal() -> None:
    s = build_user_message(
        redacted="hello [EMAIL_1]",
        original=None,
        mapping_count=None,
        mapping_kinds=[],
        config_summary=None,
    )
    assert "hello [EMAIL_1]" in s
    assert "ORIGINAL" not in s


def test_build_user_message_with_original() -> None:
    s = build_user_message(
        redacted="[EMAIL_1]",
        original="a@b.co",
        mapping_count=1,
        mapping_kinds=["EMAIL"],
        config_summary="test",
    )
    assert "a@b.co" in s
    assert "EMAIL" in s
    assert "test" in s


def test_mapping_meta(tmp_path: Path) -> None:
    p = tmp_path / "m.json"
    p.write_text(
        json.dumps({"[EMAIL_1]": "x@y.co", "[METRC_2]": "ABC"}),
        encoding="utf-8",
    )
    n, kinds = _mapping_meta(p)
    assert n == 2
    assert "EMAIL" in kinds and "METRC" in kinds


def test_config_summary(tmp_path: Path) -> None:
    p = tmp_path / "c.yaml"
    p.write_text("strains:\n  - A\nbuiltins:\n  email: false\n", encoding="utf-8")
    s = _config_summary(p)
    assert s is not None
    assert "strains" in s
    assert "email" in s
