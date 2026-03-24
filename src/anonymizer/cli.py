from __future__ import annotations

import argparse
import sys

from anonymizer.core import anonymize, load_config


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Redact customer data from prompts before OpenRouter (METRC-style IDs, lists, etc.)."
    )
    parser.add_argument(
        "-c",
        "--config",
        help="YAML config (strains, companies, extra regexes)",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Input file (UTF-8); stdin if omitted",
    )
    args = parser.parse_args()
    cfg = load_config(args.config)

    if args.path:
        with open(args.path, encoding="utf-8") as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    sys.stdout.write(anonymize(text, cfg))


if __name__ == "__main__":
    main()
