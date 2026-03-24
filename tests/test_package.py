"""Package surface and exports."""

from __future__ import annotations

import anonymizer


def test_version_defined() -> None:
    import importlib.metadata

    v = importlib.metadata.version("prompt-anonymizer")
    assert v
    parts = v.split(".")
    assert len(parts) >= 2


def test_public_exports() -> None:
    assert hasattr(anonymizer, "anonymize")
    assert hasattr(anonymizer, "load_config")
    assert callable(anonymizer.anonymize)
    assert callable(anonymizer.load_config)
