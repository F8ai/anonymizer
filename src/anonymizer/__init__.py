"""Redact customer-identifying content from text before sending to model APIs."""

from anonymizer.core import anonymize, load_config

__all__ = ["anonymize", "load_config"]
