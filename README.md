# prompt-anonymizer

Fast, local redaction for prompts and payloads **before** they go to [OpenRouter](https://openrouter.ai/) (or any other model API). The goal is to strip regulated and customer-identifying data—**PHI/PII-style identifiers** (SSN, EIN, dates of birth/encounter, payment cards, IPs, email, phone), **METRC-style** tags, and configurable **strain / company / person** phrases—so text can be logged or sent upstream with lower leakage risk.

## What it does (technical controls)

- **Built-in patterns (ordered pipeline):** Luhn-checked **payment cards**, **SSN** (dashed/spaced), **EIN**, **email**, **US phone**, validated **ISO dates** and **slash dates**, **IPv6** then **IPv4** (parsed with `ipaddress`), **METRC-like** uppercase alphanumerics (20–28 chars).
- **Lists:** YAML lists of **strains**, **companies**, and **people** (longest match first).
- **Extra regexes:** Internal codes, MRNs, order IDs, etc. (each match becomes a unique `[EXTRA_n]` with the matched text stored in the mapping).

## Reversible redaction (unredact)

Each redacted span is replaced by a **unique** placeholder like `[EMAIL_1]`, `[SSN_2]`, `[METRC_3]`. Keep the mapping **only on your side** (same sensitivity as plaintext). To restore model output or logs before internal use:

```python
from anonymizer import anonymize, load_config, unredact

cfg = load_config("config.yaml")
redacted, mapping = anonymize(raw_user_message, cfg, return_mapping=True)
# send `redacted` upstream; store `mapping` securely

restored = unredact(model_output, mapping)
```

CLI: write the JSON mapping next to runs with `--mapping-out map.json`, and restore with `anonymize-prompt --unredact --mapping map.json redacted.txt`.

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

Layout: `tests/test_builtins.py`, `tests/test_network_ids.py`, `tests/test_config_pipeline.py`, `tests/test_roundtrip.py`, `tests/test_cli.py`, `tests/test_package.py`, `tests/test_review.py`, plus `conftest.py`.

### Latency (token windows)

Measure wall-clock time for `anonymize()` on synthetic corpora sized to common context lengths (256 → 131072 tokens by default). With `tiktoken` installed, lengths use **exact** `cl100k_base` token counts; otherwise sizing uses ~4 characters per token.

```bash
pip install -e ".[benchmark]"   # optional: exact tokenization
anonymize-bench                  # full default grid (can be slow)
anonymize-bench --windows 512,1024,4096 --repeats 5 --warmup 1
anonymize-bench -c config.yaml --seed 42
```

## Usage

```bash
# stdin
echo 'Contact grow@example.com about batch 1A4FF000000012400000000' | anonymize-prompt -c config.yaml --mapping-out map.json

# file
anonymize-prompt -c config.yaml prompt.txt
```

Copy `config.example.yaml` to `config.yaml` and tune lists and `builtins` toggles.

## Expert review agent (LLM assist)

`anonymize-review` asks an OpenRouter model to **critique** redacted output (Safe Harbor–style checklist, METRC context, narrative re-ID risk). This is an **engineering assist**, **not** a HIPAA Expert Determination and **not** legal advice.

```bash
export OPENROUTER_API_KEY=...
# Prompt only (no third-party call):
anonymize-review --print-prompt --redacted redacted.txt --config config.yaml

# Full review (redacted text only — safer):
anonymize-review --redacted redacted.txt --mapping map.json -c config.yaml

# Comparative review (sends ORIGINAL to OpenRouter — use only if allowed):
anonymize-review --redacted redacted.txt --original original.txt
```

Environment: `ANONYMIZER_REVIEW_MODEL` (default `openai/gpt-4o-mini`), optional `OPENROUTER_API_URL`, `OPENROUTER_SITE_URL`, `OPENROUTER_APP_TITLE`. The `--mapping` file is summarized as **counts and placeholder kinds only** — secret values are not embedded in the prompt.

## OpenRouter integration

Run user or system content through `anonymize()` (Python) or the CLI **immediately before** building the request body you send to OpenRouter. Keep the original text only on your side if you need it for compliance; only the redacted string should leave your trust boundary.

```python
from anonymizer import anonymize, load_config

cfg = load_config("config.yaml")
safe_user_message = anonymize(raw_user_message, cfg)
# Or with mapping for later unredact: anonymize(..., return_mapping=True)
```

## License

MIT
