"""Built-in redactors: Luhn, cards, SSN, EIN, email, phone, dates."""

from __future__ import annotations

import pytest

from anonymizer.core import _luhn_valid, anonymize


class TestLuhn:
    @pytest.mark.parametrize(
        "pan",
        [
            "4111111111111111",
            "378282246310005",
            "5555555555554444",
            "6011111111111117",
        ],
    )
    def test_known_valid_test_pans(self, pan: str) -> None:
        assert _luhn_valid(pan)

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "1",
            "123456789012345",  # 15 digits wrong check
            "4111111111111112",
            "abcdefghijklmnop",
        ],
    )
    def test_invalid(self, bad: str) -> None:
        assert not _luhn_valid(bad)


class TestCreditCard:
    @pytest.mark.parametrize(
        "text,expect_card",
        [
            ("4111-1111-1111-1111", True),
            ("4111 1111 1111 1111", True),
            ("Pay 4111111111111111 now", True),
            ("4111111111111112", False),
        ],
    )
    def test_redaction(self, text: str, expect_card: bool) -> None:
        out = anonymize(text, {})
        assert ("[CARD]" in out) is expect_card

    def test_hyphen_grouped(self) -> None:
        assert anonymize("x 4111-1111-1111-1111 y", {}) == "x [CARD] y"

    def test_multiple_cards(self) -> None:
        out = anonymize("a 4111111111111111 b 5555555555554444 c", {})
        assert out.count("[CARD]") == 2


class TestSSN:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("SSN 123-45-6789 end", "SSN [SSN] end"),
            ("SSN 123 45 6789 end", "SSN [SSN] end"),
        ],
    )
    def test_formats(self, raw: str, expected: str) -> None:
        assert anonymize(raw, {}) == expected


class TestEIN:
    def test_standard(self) -> None:
        assert anonymize("EIN 12-3456789", {}) == "EIN [EIN]"


class TestEmail:
    @pytest.mark.parametrize(
        "addr",
        [
            "x@y.co",
            "User.Name+tag@sub.example.com",
        ],
    )
    def test_redacted(self, addr: str) -> None:
        out = anonymize(f"mail {addr} thanks", {})
        assert addr not in out
        assert "[EMAIL]" in out

    def test_multiple(self) -> None:
        out = anonymize("a@b.co and c@d.co", {})
        assert out.count("[EMAIL]") == 2


class TestPhone:
    @pytest.mark.parametrize(
        "phone",
        [
            "(555) 123-4567",
            "555-123-4567",
            "555.123.4567",
            "+1 555 123 4567",
        ],
    )
    def test_us_variants(self, phone: str) -> None:
        out = anonymize(f"call {phone} now", {})
        assert phone not in out
        assert "[PHONE]" in out

    def test_multiple(self) -> None:
        out = anonymize("(555) 111-1111 or (555) 222-2222", {})
        assert out.count("[PHONE]") == 2


class TestDates:
    @pytest.mark.parametrize(
        "raw,expect_date",
        [
            ("2024-06-15", True),
            ("2024-13-40", False),
            ("06/15/2024", True),
            ("99/99/2020", False),
        ],
    )
    def test_iso_and_us(self, raw: str, expect_date: bool) -> None:
        out = anonymize(f"x {raw} y", {})
        assert (raw not in out) is expect_date


class TestBuiltinToggles:
    @pytest.mark.parametrize(
        "name,sample,needle_if_off",
        [
            ("credit_card", "4111111111111111", "4111111111111111"),
            ("ssn", "123-45-6789", "123-45-6789"),
            ("ein", "12-3456789", "12-3456789"),
            ("email", "a@b.co", "a@b.co"),
            ("phone_us", "(555) 123-4567", "555"),
            ("date_iso", "2024-01-01", "2024-01-01"),
            ("date_us_slash", "01/02/2024", "01/02/2024"),
            ("ipv6", "2001:db8::1", "2001:db8::1"),
            ("ipv4", "192.168.0.1", "192.168.0.1"),
            ("metrc_like_ids", "1A4FF000000012400000000", "1A4FF000000012400000000"),
        ],
    )
    def test_each_can_be_disabled(self, name: str, sample: str, needle_if_off: str) -> None:
        cfg = {"builtins": {name: False}}
        out = anonymize(sample, cfg)
        assert needle_if_off in out
