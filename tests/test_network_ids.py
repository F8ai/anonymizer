"""IPv4, IPv6, METRC-like tokens."""

from __future__ import annotations

import re

import pytest

from anonymizer.core import anonymize


def _has_kind(out: str, kind: str) -> bool:
    return re.search(rf"\[{re.escape(kind)}_\d+\]", out) is not None


class TestIPv4:
    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "127.0.0.1",
            "10.0.0.1",
            "255.255.255.255",
        ],
    )
    def test_common_addresses(self, ip: str) -> None:
        out = anonymize(f"host {ip} port", {})
        assert ip not in out
        assert _has_kind(out, "IPV4")

    def test_invalid_not_replaced(self) -> None:
        assert "999.999.999.999" in anonymize("bad 999.999.999.999", {})

    def test_sequential_ips(self) -> None:
        out = anonymize("a 10.0.0.1 b 10.0.0.2 c", {})
        assert out.count("[IPV4_") == 2


class TestIPv6:
    def test_compressed(self) -> None:
        out = anonymize("addr 2001:db8::1 done", {})
        assert "2001:db8::1" not in out
        assert _has_kind(out, "IPV6")

    def test_full_form(self) -> None:
        ip = "2001:0db8:0000:0000:0000:0000:0000:0001"
        out = anonymize(f"x {ip} y", {})
        assert ip not in out
        assert _has_kind(out, "IPV6")

    def test_invalid_hex_preserved(self) -> None:
        bad = "12:34:56:78:90:zz:bb:cc"
        assert bad in anonymize(f"x {bad} y", {})


class TestMetrc:
    @pytest.mark.parametrize(
        "length",
        [20, 24, 28],
    )
    def test_length_boundaries(self, length: int) -> None:
        token = "A" * length
        out = anonymize(f"id {token}", {})
        assert token not in out
        assert _has_kind(out, "METRC")

    def test_too_short_preserved(self) -> None:
        token = "A" * 19
        assert token in anonymize(f"x {token} y", {})

    def test_too_long_preserved(self) -> None:
        token = "A" * 29
        assert token in anonymize(f"x {token} y", {})

    def test_lowercase_not_metrc_class(self) -> None:
        token = "a" * 24
        assert token in anonymize(token, {})
