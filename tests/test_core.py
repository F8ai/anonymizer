"""Tests for PHI/PII-style redaction (technical controls, not legal compliance)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from anonymizer.core import _luhn_valid, anonymize, load_config


class TestLuhn:
    def test_valid_visa_test_pan(self) -> None:
        assert _luhn_valid("4111111111111111")

    def test_valid_amex_test_pan(self) -> None:
        """Exercises Luhn branch where doubled digit > 9."""
        assert _luhn_valid("378282246310005")

    def test_invalid_pan(self) -> None:
        assert not _luhn_valid("4111111111111112")

    def test_wrong_length(self) -> None:
        assert not _luhn_valid("41111111111111")
        assert not _luhn_valid("")


class TestCreditCard:
    def test_visa_spaces(self) -> None:
        assert "[CARD]" in anonymize("Pay with 4111 1111 1111 1111 today", {})

    def test_amex_continuous(self) -> None:
        assert anonymize("378282246310005", {}) == "[CARD]"

    def test_visa_continuous(self) -> None:
        assert anonymize("card=4111111111111111", {}) == "card=[CARD]"

    def test_non_luhn_not_redacted(self) -> None:
        out = anonymize("not a card 4111111111111112 end", {})
        assert "4111111111111112" in out

    def test_builtin_disabled(self) -> None:
        cfg = {"builtins": {"credit_card": False}}
        assert "4111111111111111" in anonymize("4111111111111111", cfg)


class TestSSN:
    def test_dashed(self) -> None:
        assert anonymize("SSN 123-45-6789 ok", {}) == "SSN [SSN] ok"

    def test_spaced(self) -> None:
        assert anonymize("SSN 123 45 6789 ok", {}) == "SSN [SSN] ok"

    def test_disabled(self) -> None:
        cfg = {"builtins": {"ssn": False}}
        assert "123-45-6789" in anonymize("123-45-6789", cfg)


class TestEIN:
    def test_standard(self) -> None:
        assert anonymize("EIN 12-3456789", {}) == "EIN [EIN]"


class TestEmail:
    def test_basic(self) -> None:
        assert anonymize("x@y.co", {}) == "[EMAIL]"

    def test_subdomain(self) -> None:
        out = anonymize("reach me at user.name@mail.example.com thanks", {})
        assert "user.name@mail.example.com" not in out
        assert "[EMAIL]" in out


class TestPhone:
    def test_us_formats(self) -> None:
        samples = [
            "(555) 123-4567",
            "555-123-4567",
            "555.123.4567",
            "+1 555 123 4567",
        ]
        for s in samples:
            out = anonymize(f"call {s} now", {})
            assert s not in out, s
            assert "[PHONE]" in out, s


class TestDates:
    def test_iso_valid(self) -> None:
        assert anonymize("visit 2024-06-15 please", {}) == "visit [DATE] please"

    def test_iso_invalid_not_redacted(self) -> None:
        assert "2024-13-40" in anonymize("bad 2024-13-40 date", {})

    def test_us_slash_invalid_not_redacted(self) -> None:
        assert "99/99/2020" in anonymize("bad 99/99/2020 date", {})

    def test_us_slash(self) -> None:
        out = anonymize("due 06/15/2024", {})
        assert "[DATE]" in out
        assert "06/15/2024" not in out


class TestIPv4:
    def test_private(self) -> None:
        out = anonymize("server 192.168.1.1 port", {})
        assert "192.168.1.1" not in out
        assert "[IPV4]" in out

    def test_invalid_not_redacted(self) -> None:
        assert "999.999.999.999" in anonymize("bad 999.999.999.999", {})


class TestIPv6:
    def test_compressed(self) -> None:
        out = anonymize("addr 2001:db8::1 done", {})
        assert "2001:db8::1" not in out
        assert "[IPV6]" in out

    def test_invalid_hex_blob_not_replaced(self) -> None:
        """Looks like IPv6 (colons) but fails parsing — must stay in output."""
        bad = "12:34:56:78:90:zz:bb:cc"
        assert bad in anonymize(f"x {bad} y", {})


class TestMetrc:
    def test_like_token(self) -> None:
        t = "1A4FF000000012400000000"
        out = anonymize(f"batch {t}", {})
        assert t not in out
        assert "[METRC_ID]" in out

    def test_disabled(self) -> None:
        t = "1A4FF000000012400000000"
        cfg = {"builtins": {"metrc_like_ids": False}}
        assert t in anonymize(t, cfg)


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
        assert out.count("[STRAIN]") == 1

    def test_companies(self) -> None:
        cfg = {"companies": ["Acme Grow LLC"]}
        assert "Acme Grow LLC" not in anonymize("ship to Acme Grow LLC", cfg)

    def test_people(self) -> None:
        cfg = {"people": ["Jane Q. Patient"]}
        out = anonymize("Patient Jane Q. Patient arrived", cfg)
        assert "Jane Q. Patient" not in out
        assert "[PERSON]" in out


class TestExtraPatterns:
    def test_custom_regex(self) -> None:
        cfg = {
            "extra_patterns": [
                {"pattern": r"\bMRN-\d+\b", "replacement": "[MRN]"},
            ]
        }
        assert anonymize("see MRN-908172", cfg) == "see [MRN]"


class TestLoadConfig:
    def test_none_path(self) -> None:
        assert load_config(None) == {}

    def test_missing_file(self) -> None:
        assert load_config("/nonexistent/nope.yaml") == {}

    def test_roundtrip(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".yaml",
            delete=False,
            encoding="utf-8",
        ) as f:
            f.write("people:\n  - Test User\n")
            path = f.name
        try:
            cfg = load_config(path)
            assert cfg["people"] == ["Test User"]
        finally:
            Path(path).unlink()


class TestPipelineOrder:
    def test_ssn_not_broken_by_metrc(self) -> None:
        """SSN runs before METRC-style in pipeline; dashed SSN is distinct."""
        out = anonymize("id 123-45-6789", {})
        assert out == "id [SSN]"

    def test_empty_and_unicode(self) -> None:
        assert anonymize("", {}) == ""
        assert anonymize("café naïve", {}) == "café naïve"


class TestBuiltinNames:
    def test_all_builtin_keys_exist_in_pipeline(self) -> None:
        from anonymizer.core import _BUILTIN_PIPELINE

        names = {n for n, _ in _BUILTIN_PIPELINE}
        cfg = {"builtins": {k: False for k in names}}
        raw = "plain text without sensitive tokens"
        assert anonymize(raw, cfg) == raw


class TestRegressionHIPAALike:
    """End-to-end mixed PHI-style strings."""

    def test_clinical_snippet(self) -> None:
        text = (
            "Patient Jane Q. Patient DOB 04/12/1985 MRN-1002 "
            "contact patient@email.com (415) 555-0199 "
            "insurance 123-45-6789 visit 2025-01-10"
        )
        cfg = {
            "people": ["Jane Q. Patient"],
            "extra_patterns": [
                {"pattern": r"\bMRN-\d+\b", "replacement": "[MRN]"},
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
    cfg = {"extra_patterns": [bad_entry, {"pattern": r"A\d", "replacement": "[OK]"}]}
    assert anonymize("A1", cfg) == "[OK]"
