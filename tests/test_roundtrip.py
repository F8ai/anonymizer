"""Round-trip: anonymize + unredact restores original text."""

from __future__ import annotations

import json

from anonymizer.core import anonymize, unredact


def test_unredact_empty_mapping() -> None:
    assert unredact("hello", {}) == "hello"


def test_unredact_longest_placeholder_first() -> None:
    m = {"[EMAIL_1]": "a@b.co", "[EMAIL_10]": "z@z.co"}
    assert unredact("x [EMAIL_10] [EMAIL_1] y", m) == "x z@z.co a@b.co y"


def test_roundtrip_mixed_phi() -> None:
    raw = (
        "Email a@b.co and SSN 123-45-6789 "
        "METRC 1A4FF000000012400000000 end"
    )
    out, mapping = anonymize(raw, return_mapping=True)
    assert "[EMAIL_" in out and "[SSN_" in out and "[METRC_" in out
    assert unredact(out, mapping) == raw


def test_roundtrip_with_config_lists() -> None:
    raw = "Patient Jane Q. Doe visited"
    cfg = {"people": ["Jane Q. Doe"]}
    out, mapping = anonymize(raw, cfg, return_mapping=True)
    assert "Jane" not in out
    assert unredact(out, mapping) == raw


def test_anonymize_messages_multimodal_text() -> None:
    from anonymizer.core import anonymize_messages

    msgs = [
        {
            "role": "user",
            "content": [{"type": "text", "text": "reach x@y.co"}],
        }
    ]
    out, _ = anonymize_messages(msgs, {})
    assert "[EMAIL_" in out[0]["content"][0]["text"]


def test_anonymize_messages_skips_system() -> None:
    from anonymizer.core import anonymize_messages

    msgs = [
        {"role": "system", "content": "x@y.co"},
        {"role": "user", "content": "hi"},
    ]
    out, m = anonymize_messages(msgs, {})
    assert "x@y.co" in out[0]["content"]
    assert m == {}


def test_anonymize_messages_shared_mapping() -> None:
    from anonymizer.core import anonymize_messages

    msgs = [
        {"role": "user", "content": "a@b.co"},
        {"role": "user", "content": "same a@b.co"},
    ]
    out, mapping = anonymize_messages(msgs, {})
    assert out[0]["content"] == "[EMAIL_1]"
    assert out[1]["content"] == "same [EMAIL_2]"
    assert len(mapping) == 2


def test_mapping_json_roundtrip() -> None:
    raw = "x@y.co"
    out, mapping = anonymize(raw, return_mapping=True)
    blob = json.dumps(mapping)
    m2 = json.loads(blob)
    assert unredact(out, m2) == raw
