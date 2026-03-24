"""load_config, phrase lists, extra_patterns, pipeline behavior."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

import re

from anonymizer.core import _BUILTIN_PIPELINE, anonymize, load_config


def _has_kind(out: str, kind: str) -> bool:
    return re.search(rf"\[{re.escape(kind)}_\d+\]", out) is not None


class TestLoadConfig:
    def test_none_path(self) -> None:
        assert load_config(None) == {}

    def test_missing_file(self) -> None:
        assert load_config("/nonexistent/nope.yaml") == {}

    def test_empty_file_is_empty_dict(self, write_yaml) -> None:
        p = write_yaml("empty.yaml", "")
        assert load_config(p) == {}

    def test_roundtrip(self, tmp_path: Path) -> None:
        p = tmp_path / "c.yaml"
        p.write_text("people:\n  - Test User\n", encoding="utf-8")
        cfg = load_config(p)
        assert cfg["people"] == ["Test User"]

    def test_path_as_str(self, tmp_path: Path) -> None:
        p = tmp_path / "c.yaml"
        p.write_text("strains:\n  - X\n", encoding="utf-8")
        cfg = load_config(str(p))
        assert cfg["strains"] == ["X"]


class TestPhraseLists:
    def test_strains_longest_first(self) -> None:
        cfg = {
            "strains": [
                "Blue Dream",
                "Blue Dream Haze",
            ]
        }
        out = anonymize("Try Blue Dream Haze first", cfg)
        assert "Blue Dream" not in out
        assert out.count("[STRAIN_") == 1

    def test_duplicates_and_whitespace_normalized(self) -> None:
        cfg = {"companies": ["  Acme  ", "Acme", "Acme"]}
        out = anonymize("Acme and Acme", cfg)
        assert out == "[COMPANY_1] and [COMPANY_2]"

    def test_case_insensitive(self) -> None:
        cfg = {"people": ["John Smith"]}
        out = anonymize("JOHN SMITH here", cfg)
        assert _has_kind(out, "PERSON")
        assert "SMITH" not in out

    def test_regex_special_chars_in_phrase(self) -> None:
        cfg = {"companies": ["Acme (West)"]}
        out = anonymize("Ship to Acme (West)", cfg)
        assert "Acme (West)" not in out
        assert _has_kind(out, "COMPANY")

    def test_empty_list_entries_ignored(self) -> None:
        cfg = {"strains": ["", "  ", "Gelato"]}
        assert "Gelato" not in anonymize("Gelato", cfg)

    def test_order_strains_before_companies_same_pipeline(self) -> None:
        """Both applied after builtins; strains first then companies in code."""
        cfg = {"strains": ["X"], "companies": ["Y"]}
        out = anonymize("X Y", cfg)
        assert _has_kind(out, "STRAIN") and _has_kind(out, "COMPANY")


class TestExtraPatterns:
    def test_extra_pattern_match(self) -> None:
        cfg = {"extra_patterns": [{"pattern": r"\bFOO\d+\b"}]}
        assert anonymize("FOO99", cfg) == "[EXTRA_1]"

    def test_mrn_pattern(self) -> None:
        cfg = {
            "extra_patterns": [
                {"pattern": r"\bMRN-\d+\b"},
            ]
        }
        assert anonymize("see MRN-908172", cfg) == "see [EXTRA_1]"

    def test_multiple_rules(self) -> None:
        cfg = {
            "extra_patterns": [
                {"pattern": r"\bA\d\b"},
                {"pattern": r"\bB\d\b"},
            ]
        }
        assert anonymize("A1 B2", cfg) == "[EXTRA_1] [EXTRA_2]"


@pytest.mark.parametrize(
    "bad_entry",
    [
        None,
        "not a dict",
        {},
        {"replacement": "[X]"},
    ],
)
def test_extra_patterns_skips_invalid_entries(bad_entry: object) -> None:
    cfg = {"extra_patterns": [bad_entry, {"pattern": r"A\d"}]}
    assert anonymize("A1", cfg) == "[EXTRA_1]"


class TestPipeline:
    def test_builtin_order_matches_documented_pipeline(self) -> None:
        names = [n for n, _ in _BUILTIN_PIPELINE]
        assert names[0] == "credit_card"
        assert names[-1] == "metrc_like_ids"

    def test_all_builtins_off_pass_through(self) -> None:
        names = {n for n, _ in _BUILTIN_PIPELINE}
        cfg = {"builtins": {k: False for k in names}}
        raw = "plain text without sensitive tokens 123"
        assert anonymize(raw, cfg) == raw

    def test_idempotent_on_already_redacted(self) -> None:
        once = anonymize("a@b.co 123-45-6789", {})
        twice = anonymize(once, {})
        assert once == twice

    def test_empty_string(self) -> None:
        assert anonymize("", {}) == ""

    def test_unicode_preserved(self) -> None:
        assert anonymize("café naïve 北京", {}) == "café naïve 北京"


class TestRegressionMixed:
    def test_clinical_snippet(self) -> None:
        text = (
            "Patient Jane Q. Patient DOB 04/12/1985 MRN-1002 "
            "contact patient@email.com (415) 555-0199 "
            "insurance 123-45-6789 visit 2025-01-10"
        )
        cfg = {
            "people": ["Jane Q. Patient"],
            "extra_patterns": [
                {"pattern": r"\bMRN-\d+\b"},
            ],
        }
        out = anonymize(text, cfg)
        assert "Jane Q. Patient" not in out
        assert "patient@email.com" not in out
        assert "(415) 555-0199" not in out
        assert "123-45-6789" not in out
        assert "2025-01-10" not in out
        assert "04/12/1985" not in out
        assert "MRN-1002" not in out


class TestStress:
    def test_large_text_few_matches(self) -> None:
        chunk = "word " * 5000
        out = anonymize(chunk + " a@b.co " + chunk, {})
        assert _has_kind(out, "EMAIL")
        assert out.count("[EMAIL_") == 1
