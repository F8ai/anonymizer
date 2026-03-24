# prompt-anonymizer

Fast, local redaction for prompts and payloads **before** they go to [OpenRouter](https://openrouter.ai/) (or any other model API). The goal is to strip regulated and customer-identifying data—**PHI/PII-style identifiers** (SSN, EIN, dates of birth/encounter, payment cards, IPs, email, phone), **METRC-style** tags, and configurable **strain / company / person** phrases—so text can be logged or sent upstream with lower leakage risk.

## What it does (technical controls)

- **Built-in patterns (ordered pipeline):** Luhn-checked **payment cards**, **SSN** (dashed/spaced), **EIN**, **email**, **US phone**, validated **ISO dates** and **slash dates**, **IPv6** then **IPv4** (parsed with `ipaddress`), **METRC-like** uppercase alphanumerics (20–28 chars).
- **Lists:** YAML lists of **strains**, **companies**, and **people** (longest match first).
- **Extra regexes:** Internal codes, MRNs, order IDs, etc.

This is a **deterministic** filter, not clinical NER. It does **not** reliably remove arbitrary person names, street addresses, or narrative diagnoses without you supplying phrases or extra patterns. **HIPAA compliance** is a program (risk analysis, minimum necessary, access controls, encryption, BAAs, training, audit), not a single library—use this as one technical control alongside organizational and legal measures.

## Install

```bash
pip install -e .
```

### Development & tests

```bash
pip install -e ".[dev]"
pytest tests/ --cov=anonymizer --cov-fail-under=90
```

Layout: `tests/test_builtins.py` (Luhn, cards, SSN, EIN, email, phone, dates, toggles), `tests/test_network_ids.py` (IPv4/IPv6, METRC-like), `tests/test_config_pipeline.py` (YAML, lists, extras, stress), `tests/test_cli.py`, `tests/test_package.py`, plus `conftest.py` for shared fixtures.

## Usage

```bash
# stdin
echo 'Contact grow@example.com about batch 1A4FF000000012400000000' | anonymize-prompt -c config.yaml

# file
anonymize-prompt -c config.yaml prompt.txt
```

Copy `config.example.yaml` to `config.yaml` and tune lists and `builtins` toggles.

## OpenRouter integration

Run user or system content through `anonymize()` (Python) or the CLI **immediately before** building the request body you send to OpenRouter. Keep the original text only on your side if you need it for compliance; only the redacted string should leave your trust boundary.

```python
from anonymizer import anonymize, load_config

cfg = load_config("config.yaml")
safe_user_message = anonymize(raw_user_message, cfg)
```

## License

MIT
