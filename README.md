# prompt-anonymizer

Fast, local redaction for prompts and payloads **before** they go to [OpenRouter](https://openrouter.ai/) (or any other model API). The goal is to strip customer-identifying and regulated data—METRC-style identifiers, company names, strain names, emails, and phone numbers—so prompts can be logged or sent upstream without leaking PII.

## What it does

- **Built-in patterns:** US-style phones, email addresses, and 20–28 character uppercase alphanumeric tokens (METRC package label–like), each replaceable with neutral placeholders.
- **Lists:** Optional YAML lists of **strain** and **company** strings (longest match first to avoid partial leaks).
- **Extra regexes:** Add your own patterns (order IDs, internal codes, etc.).

This is a deterministic filter, not ML-based NER. Tune `config.yaml` for your data; false positives on the METRC-like rule are possible if your text has unrelated long uppercase tokens—disable `metrc_like_ids` in config if needed.

## Install

```bash
pip install -e .
```

## Usage

```bash
# stdin
echo 'Contact grow@example.com about batch 1A4FF000000012400000000' | anonymize-prompt -c config.yaml

# file
anonymize-prompt -c config.yaml prompt.txt
```

Copy `config.example.yaml` to `config.yaml` and fill in strains, companies, and any extra regexes.

## OpenRouter integration

Run user or system content through `anonymize()` (Python) or the CLI **immediately before** building the request body you send to OpenRouter. Keep the original text only on your side if you need it for compliance; only the redacted string should leave your trust boundary.

```python
from anonymizer import anonymize, load_config

cfg = load_config("config.yaml")
safe_user_message = anonymize(raw_user_message, cfg)
```

## License

MIT
